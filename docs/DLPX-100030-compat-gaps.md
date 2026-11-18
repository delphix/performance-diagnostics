# DLPX-100030 — Fluentd Compat Metric Gaps vs Java

Analysis of schema/semantic differences between Java's `pushInsightMetric` output
and the Telegraf fluentd processor output for the same metric names.

Jira tracking tickets: DLPX-101020, DLPX-101021, DLPX-101022
PR: https://github.com/delphix/performance-diagnostics/pull/135

---

## Gap 1 — system.net.total.bytes: missing networkInterface dimension

**Jira:** [DLPX-101020](https://perforce.atlassian.net/browse/DLPX-101020)
**File:** `telegraf/telegraf.processors.fluentd` lines 260-287

### Old (Java)
```json
{
  "metric_name": "system.net.total.bytes",
  "_value": 91739,
  "data": {
    "inBytes": 13290,
    "inPackets": 87,
    "networkInterface": "enx02ffd5b31385",
    "outBytes": 78449,
    "outPackets": 118
  }
}
```
Java emitted **one event per network interface** with `networkInterface` as a data dimension.

### New (Telegraf)
```json
{
  "metric_name": "system.net.total.bytes",
  "_value": 84875,
  "data": {
    "inBytes": 8606,
    "inPackets": 71,
    "outBytes": 76269,
    "outPackets": 100
  }
}
```
Telegraf processor aggregates **all interfaces into one event**. `networkInterface` absent.

### Splunk dashboard impact
Any search filtering `networkInterface=eth0` or grouping by interface → **0 results**.

### Why this happened
The processor uses shared accumulators (`net_d_in`, `net_d_out`) across all interfaces,
emitting a single `flush_counter("net", ...)` event per bucket. Per-interface delta
tracking already exists (`cumulative_delta("net_r_" + iface, ...)`) but the flush
does not split by interface.

### Fix path (DLPX-101020)
Per-interface bucket state + per-interface flush logic → one `system.net.total.bytes`
event per active interface with `data.networkInterface` tag. ~30-line change, no
InfluxDB impact (all `system.*` namedropped from both InfluxDB outputs).

### Analysis status
- [ ] Confirm how many customers have per-interface Splunk/Datadog dashboard filters
- [ ] Decision: fix or document
- [ ] If fix: implement + verify on engine

---

## Gap 2 — system.disk.ops.count: schema diverges from Java

**Jira:** [DLPX-101021](https://perforce.atlassian.net/browse/DLPX-101021)
**File:** `telegraf/telegraf.processors.fluentd` lines 289-330

### Old (Java)
```json
{
  "metric_name": "system.disk.ops.count",
  "type": "counter",
  "_value": 2,
  "data": {
    "op": "read",
    "count": 2,
    "avgLatency": 624232,
    "latency": { "500000": 1, "800000": 1 },
    "throughput": 39936
  }
}
```
Java emitted **separate events per op direction** (`op: read` / `op: write`) with
per-op average latency, latency histogram buckets, and throughput.

### New (Telegraf)
```json
{
  "metric_name": "system.disk.ops.count",
  "type": "counter",
  "_value": 1938,
  "data": {
    "reads": 2,
    "writes": 1936,
    "bytesRead": 10240,
    "bytesWritten": 25444864,
    "readTime": 1,
    "writeTime": 1969
  }
}
```
Single aggregated event. No `op` dimension, no latency, no throughput.

### Splunk dashboard impact
- Searches using `op=read` or `op=write` → **0 results**
- `avgLatency` field → **absent**
- Latency histogram → **absent**
- Throughput per op → **absent**
- Disk I/O latency and throughput dashboard widgets → **break entirely**

### Root cause
Telegraf's `diskio` input provides cumulative counters (reads/writes/bytes/times)
but no per-op latency data. Backend-IO latency lives in `hist_estat_backend-io`
(a separate measurement, already in InfluxDB for DCT Grafana). Bridging the gap
to Splunk/Datadog would require sourcing from that measurement and reshaping into
Java's histogram format — non-trivial.

### Fix path options (DLPX-101021)
1. **Source from hist_estat_backend-io**: pull avgLatency and histogram from that
   measurement's starlark processor and add to disk compat event. Complex — requires
   cross-measurement coordination in starlark.
2. **Emit per-op events from diskio**: split reads/writes into separate events with
   `op` tag, derive avgLatency from readTime/reads and writeTime/writes (imprecise —
   readTime is total ms, not per-op). Missing histogram.
3. **Document the loss**: add to PR "What customers lose" section with migration guidance.

### Analysis status
- [ ] Confirm customer usage of disk latency/throughput Splunk dashboards
- [ ] Decision: fix path 1, 2, or document
- [ ] If fix: validate latency derivation from diskio readTime/reads

---

## Gap 3 — system.tcp.total.bytes: per-connection dimensions dropped (intentional)

**Jira:** [DLPX-101022](https://perforce.atlassian.net/browse/DLPX-101022)
**File:** `telegraf/telegraf.processors.fluentd` lines 328-365

### Old (Java)
```json
{
  "metric_name": "system.tcp.total.bytes",
  "data": {
    "localAddress": "10.110.251.222",
    "remoteAddress": "10.110.20.143",
    "service": "omniorb",
    "congestionWindowSize": 5369400,
    "receiveWindowSize": 126450310,
    "sendWindowSize": 3527626,
    "roundTripTime": 104160,
    "unacknowledgedBytes": 0,
    "unsentBytes": 0,
    "inBytes": 6056,
    "outBytes": 69885,
    "retransmittedSegs": 0
  }
}
```

### New (Telegraf)
```json
{
  "metric_name": "system.tcp.total.bytes",
  "data": {
    "inBytes": 9597,
    "outBytes": 0,
    "retransmittedSegs": 0
  }
}
```
Intentional reduction — TCP per-connection dimensions were removed to avoid cardinality
explosion on Oracle dNFS and Elastic Data engines (hundreds of connections per VDB host).
Documented in PR description "What customers do lose".

### Splunk dashboard impact
- `localAddress` / `remoteAddress` / `service` filtering → **0 results**
- Window sizes (`congestionWindowSize` etc.) → **absent**
- `roundTripTime` → **absent**
- Per-connection bandwidth breakdown → **absent**
- Total TCP throughput (inBytes + outBytes) still present ✓

### Analysis status
- [x] Intentional, documented in PR
- [ ] Release notes explicitly listing removed TCP dimensions
- [ ] Customer migration guidance for Datadog (x2) and Dynatrace (x1) custom templates

---

## Summary table

| Metric | Gap | Jira | Intentional? | Fix complexity |
|--------|-----|------|-------------|----------------|
| system.net.total.bytes | Missing `networkInterface` dimension | DLPX-101020 | No — oversight | Low (~30 lines) |
| system.disk.ops.count | Schema divergence (no op/latency/throughput) | DLPX-101021 | No — input limitation | High or document |
| system.tcp.total.bytes | Per-connection dimensions dropped | DLPX-101022 | Yes — cardinality | Document only |
