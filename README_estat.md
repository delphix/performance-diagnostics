## Overview

`estat` - extensible performance observability tool for Delphix Dynamic Data Platform.  

This tool mainly uses `eBPF` programs with a `BCC` front-end to collect and output performance statistics from the kernel via `kprobes`.  
It is made up of the following components:

- `cmd/estat`
     - Main script that provides a framework for common I/O data aggregation and drives execution of various *performance data collectors*. 
- `lib/bcchelper.py`, `lib/bcc_helper.h`
     - Helper script providing additional framework for data aggregation methods (scalar and histogram) and output formatting.
- `bpf/estat/*`
     - eBPF programs which form the *performance data collectors* (like `bpf/estat/zio.c`) using above framework.
- `bpf/standalone/*`
     - Standalone scripts that form additional *performance data collectors* and mostly self contained.

## Installation

`estat` is already installed on the Delphix Dynamic Data Platform.

## Usage

### Example

```
$ sudo ./cmd/estat zio -mlza domain0 3
11/14/19 - 02:58:30 UTC

 Tracing enabled... Hit Ctrl-C to end.
   microseconds                                            write, asyncw
value range                 count ------------- Distribution -------------
[400, 500)                     36 |@@@@@@@@@@@@@@@
[500, 600)                     37 |@@@@@@@@@@@@@@@@
[600, 700)                      9 |@@@@
[700, 800)                     10 |@@@@
[800, 900)                      3 |@
[900, 1000)                     1 |@

   bytes                                                   write, asyncw
value range                 count ------------- Distribution -------------
[512, 1K)                      28 |@@@@@@@@@@@@
[1K, 2K)                       12 |@@@@@
[2K, 4K)                       23 |@@@@@@@@@@
[4K, 8K)                        7 |@@@
[8K, 16K)                      20 |@@@@@@@@
[16K, 32K)                      2 |@
[32K, 64K)                      4 |@@

   microseconds                                             write, syncw
value range                 count ------------- Distribution -------------
[400, 500)                      1 |@
[500, 600)                      8 |@@@@@@@@@@
[600, 700)                     12 |@@@@@@@@@@@@@@@
[700, 800)                      7 |@@@@@@@@@
[800, 900)                      1 |@
[1000, 2000)                    1 |@

   bytes                                                    write, syncw
value range                 count ------------- Distribution -------------
[1K, 2K)                       12 |@@@@@@@@@@@@@@@
[8K, 16K)                      12 |@@@@@@@@@@@@@@@
[16K, 32K)                      6 |@@@@@@@

                                       iops(/s)  avg latency(us)       stddev(us)  throughput(k/s)
 write, asyncw                               32              554            14171              481
 write, syncw                                10              657            13653              284


                                       iops(/s)  throughput(k/s)
 total                                       42              765

```

##  Performance data collector structure

The main `cmd/estat` script adds the needed boiler plate for:  

- `BCC` front-end (loading the eBPF program, attaching probes etc).
- Common I/O data aggregation with: `AGGREGATE_DATA()` and `aggregate1(), aggregate2(), aggregate3()` depending on options (`lzqy`) passed
- Helper (`bcchelper`) for various aggregation methods (sum, average, log, log linear histograms etc) and printing formatted output.  

An `estat` performance data collector or program then, has the below structure leveraging the framework mentioned above  

- Defines a base hash map for collecting data  
    For example:

    ```
    // Structure to hold thread local data
    typedef struct {
       u64 ts;
    } zio_data_t;
    BPF_HASH(zio_base_data, zio_t *, zio_data_t);
    ```

- Uses kprobes (`kprobe`, `kretprobe`) for dynamic tracing and `AGGREGATE_DATA()` for any I/O aggregation  
    For example:

    ```
    // @@ kretprobe|vdev_queue_io_to_issue|vdev_queue_issue
    int vdev_queue_issue(struct pt_regs *ctx)
    {
         zio_data_t data = {};
         data.ts = bpf_ktime_get_ns();
     
         if (zio == NULL)
            return 0;
     
         zio_base_data.update(&zio, &data);
     
         return 0;
    }
     
     // @@ kprobe|vdev_queue_io_done|vdev_queue_done
    int vdev_queue_done(struct pt_regs *ctx, zio_t *zio)
    {
        u64 ts = bpf_ktime_get_ns();
        zio_data_t *data = zio_base_data.lookup(&zio);
        if (data == 0) {
            return 0;   // missed issue
        }
    
        u64 delta = ts - data->ts;
        char name[NAME_LENGTH];
        char axis[AXIS_LENGTH];
    
        if (zio->io_type == 1) {
            __builtin_memcpy(&name, "read ", OP_LENGTH + 1);
        } else if (zio->io_type == 2) {
            __builtin_memcpy(&name, "write ", OP_LENGTH + 1);
        }
       if (zio->io_priority == 0) {
           __builtin_memcpy(&axis, "syncr", PRIORITY_LENGTH);
       } else if (zio->io_priority == 1) {
           __builtin_memcpy(&axis, "syncw", PRIORITY_LENGTH);
       }
    
       AGGREGATE_DATA(name, axis, delta, zio->io_size);
       zio_base_data.delete(&zio);
    
       return 0;
    }
    ```

- The statements starting with `// @@ ` (example above) **are required** for the probe functions to be attached via a pyton BPF object.  
  The statement specifies the text necessary to complete an attach call when appened to `b.attach_`.  
  For example:

      `// @@ kprobe|vdev_queue_io_done|vdev_queue_done`

    leads to this attach call:

      `b.attach_kprobe(event="vdev_queue_io_done", fn_name="vdev_queue_done")`

- The `name` and optionally an `axis` define an `I/O type` for which aggregations are done and output.


