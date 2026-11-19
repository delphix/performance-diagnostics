#!/usr/bin/env python3
# Copyright (c) 2026 by Delphix. All rights reserved.
#
# Fixtures for the bucket sweep in telegraf/telegraf.processors.fluentd.
#
# The sweep is what flushes a key nothing reports for any more — a TCP
# endpoint that closes, an interface that goes away — and it has to do
# that off a clock it reconstructs from metric timestamps alone. Inputs
# disagree about the time (connstat-stats.sh:49-60 prints each batch
# under the previous header's timestamp, so tcp_stats trails cpu and
# net), and the clock itself steps, forwards on an NTP correction and
# backwards on a snapshot revert. The four cases below are the ones
# where a reconstructed clock goes wrong; each has produced a defect.
#
# Every case runs the processor the way the engine does: the real
# telegraf binary, the config file out of this repo, line protocol in
# and line protocol out. Nothing here re-implements the Starlark.
#
# Usage: scripts/test-fluentd-sweep.py [-v]
# Exit 0 all cases pass, 1 a case failed, 2 telegraf is not installed.

import os
import shutil
import subprocess
import sys
import tempfile

BUCKET_NS = 60 * 1000 * 1000 * 1000
SAMPLE_NS = 10 * 1000 * 1000 * 1000
SAMPLES_PER_BUCKET = 6

# An arbitrary bucket to anchor the fixtures on; nothing depends on the
# wall-clock date, only on the differences between timestamps.
BASE = 29000000

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSOR = os.path.join(REPO, "telegraf", "telegraf.processors.fluentd")

TCP_KEY = ("10.0.0.1", "10.0.0.2", "https")

CONFIG = """[agent]
  omit_hostname = true
  metric_batch_size = 100000
  metric_buffer_limit = 1000000
[[inputs.file]]
  files = ["%s"]
  data_format = "influx"
[[outputs.file]]
  files = ["%s"]
  data_format = "influx"

"""


class Metric(object):
    def __init__(self, name, tags, fields, ts):
        self.name = name
        self.tags = tags
        self.fields = fields
        self.ts = ts

    @property
    def bucket(self):
        return self.ts // BUCKET_NS

    def __repr__(self):
        return "%s %s %s @%d" % (self.name, self.tags, self.fields,
                                 self.bucket)


class Gen(object):
    """Line protocol for the three inputs the sweep clock runs off.

    net and tcp_stats byte counters are cumulative, as the real inputs
    report them, so every sample adds a fixed delta the processor has
    to recover.
    """

    def __init__(self):
        self.counters = {}

    def _bump(self, key, step):
        self.counters[key] = self.counters.get(key, 0) + step
        return self.counters[key]

    def cpu(self, ts):
        return ("cpu,cpu=cpu-total usage_user=10,usage_nice=0,"
                "usage_system=5,usage_irq=0,usage_softirq=0,"
                "usage_idle=85,usage_iowait=0,usage_steal=0 %d" % ts)

    def net(self, iface, ts):
        recv = self._bump("net_r_" + iface, 1000)
        sent = self._bump("net_s_" + iface, 2000)
        rpkt = self._bump("net_rp_" + iface, 10)
        spkt = self._bump("net_sp_" + iface, 20)
        return ("net,interface=%s bytes_recv=%di,bytes_sent=%di,"
                "packets_recv=%di,packets_sent=%di %d"
                % (iface, recv, sent, rpkt, spkt, ts))

    def tcp(self, key, ts):
        laddr, raddr, service = key
        name = "tcp_%s_%s_%s" % key
        inb = self._bump(name + "_in", 3000)
        outb = self._bump(name + "_out", 4000)
        return ("tcp_stats,laddr=%s,raddr=%s,service=%s "
                "inbytes=%di,outbytes=%di,retranssegs=0i,suna=100i,"
                "unsent=50i,swnd=1000i,cwnd=2000i,rwnd=3000i,rtt=5i,"
                "connections=1i %d"
                % (laddr, raddr, service, inb, outb, ts))


def parse(line):
    parts = line.split(" ")
    if len(parts) != 3:
        return None
    head, fieldstr, ts = parts
    bits = head.split(",")
    tags = {}
    for kv in bits[1:]:
        k, _, v = kv.partition("=")
        tags[k] = v
    fields = {}
    for kv in fieldstr.split(","):
        k, _, v = kv.partition("=")
        fields[k] = v.rstrip("i")
    return Metric(bits[0], tags, fields, int(ts))


def run_chain(lines, verbose=False):
    """Push <lines> through the repo's processor and return what the
    chain emitted, in order."""
    workdir = tempfile.mkdtemp(prefix="fluentd-sweep-")
    try:
        inp = os.path.join(workdir, "in.lp")
        outp = os.path.join(workdir, "out.lp")
        cfg = os.path.join(workdir, "telegraf.conf")
        with open(inp, "w") as f:
            f.write("\n".join(lines) + "\n")
        with open(PROCESSOR) as f:
            processor = f.read()
        with open(cfg, "w") as f:
            f.write(CONFIG % (inp, outp) + processor)
        env = dict(os.environ)
        env["DELPHIX_SYSTEM_UUID"] = "00000000-0000-0000-0000-000000000000"
        env["DELPHIX_SYSTEM_VERSION"] = "test"
        env["DELPHIX_NCPU"] = "4"
        proc = subprocess.run(["telegraf", "--once", "--config", cfg],
                              env=env, capture_output=True, text=True)
        if proc.returncode != 0:
            sys.stderr.write(proc.stderr)
            raise SystemExit("telegraf exited %d" % proc.returncode)
        if "E!" in proc.stderr:
            sys.stderr.write(proc.stderr)
            raise SystemExit("telegraf reported an error")
        out = []
        if os.path.exists(outp):
            with open(outp) as f:
                for line in f:
                    line = line.strip()
                    if not line.startswith("system."):
                        continue
                    m = parse(line)
                    if m:
                        out.append(m)
        if verbose:
            for m in out:
                print("    %r" % m)
        return out
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def net_events(out, iface):
    return [m for m in out if m.name == "system.net.total"
            and m.tags.get("data.networkInterface") == iface]


def tcp_events(out):
    return [m for m in out if m.name == "system.tcp.total"]


def case_lagging_input(verbose):
    """One input two buckets behind the others.

    The lagging metric pulls the sweep clock back and the next on-time
    one pushes it forward, so without a high-water mark on the stale
    pass the lagging key's bucket is swept on every crossing and comes
    out as a string of fragments with its counter deltas zeroed.
    """
    gen = Gen()
    lines = []
    for i in range(10 * SAMPLES_PER_BUCKET):
        ts = BASE * BUCKET_NS + i * SAMPLE_NS
        lines.append(gen.cpu(ts))
        lines.append(gen.net("eth0", ts))
        lines.append(gen.tcp(TCP_KEY, ts - 2 * BUCKET_NS))
    out = run_chain(lines, verbose)
    events = tcp_events(out)
    failures = []
    if len(events) < 5:
        failures.append("expected a tcp event per bucket, got %d"
                        % len(events))
    seen = {}
    for m in events:
        key = (m.tags.get("data.service"), m.bucket)
        seen[key] = seen.get(key, 0) + 1
        if int(m.tags.get("data.inBytes", "0")) == 0:
            failures.append("bucket %d emitted inBytes=0" % m.bucket)
    for key in sorted(seen):
        if seen[key] > 1:
            failures.append("bucket %d emitted %d times for %s"
                            % (key[1], seen[key], key[0]))
    return failures


def case_quiet_before_retreat(verbose):
    """A key that goes quiet just before a backward clock step.

    Its bucket sits above the retreated clock, which the forward stale
    pass only ever reaches from below, so without a flush on the
    retreat itself the key holds its final event and its state until
    real time climbs back past the step.
    """
    gen = Gen()
    lines = []
    for i in range(3 * SAMPLES_PER_BUCKET):
        ts = BASE * BUCKET_NS + i * SAMPLE_NS
        lines.append(gen.cpu(ts))
        lines.append(gen.net("eth0", ts))
        lines.append(gen.net("eth1", ts))
    last_bucket = (BASE * BUCKET_NS
                   + (3 * SAMPLES_PER_BUCKET - 1) * SAMPLE_NS) // BUCKET_NS
    # The clock steps back 20 buckets and real time runs on from there.
    # eth1 never reports again.
    for i in range(5 * SAMPLES_PER_BUCKET):
        ts = (BASE - 20) * BUCKET_NS + i * SAMPLE_NS
        lines.append(gen.cpu(ts))
        lines.append(gen.net("eth0", ts))
    out = run_chain(lines, verbose)
    final = [m for m in net_events(out, "eth1") if m.bucket == last_bucket]
    if not final:
        return ["eth1 never emitted its final bucket %d; emitted %s"
                % (last_bucket,
                   sorted(m.bucket for m in net_events(out, "eth1")))]
    return []


def case_stale_after_retreat(verbose):
    """The stale pass after a backward clock step.

    A key that goes quiet after the step is in the ordinary business of
    the forward stale pass, which must keep running on the retreated
    clock rather than waiting for real time to climb back to the
    pre-step high-water mark.
    """
    gen = Gen()
    lines = []
    for i in range(3 * SAMPLES_PER_BUCKET):
        ts = BASE * BUCKET_NS + i * SAMPLE_NS
        lines.append(gen.cpu(ts))
        lines.append(gen.net("eth0", ts))
        lines.append(gen.net("eth1", ts))
    # The clock steps back 20 buckets. eth1 reports once from the new
    # time and then goes quiet; the sweep owes it one event two buckets
    # later, long before real time reaches the pre-step mark.
    quiet_bucket = BASE - 20
    for i in range(8 * SAMPLES_PER_BUCKET):
        ts = (BASE - 20) * BUCKET_NS + i * SAMPLE_NS
        lines.append(gen.cpu(ts))
        lines.append(gen.net("eth0", ts))
        if i == 0:
            lines.append(gen.net("eth1", ts))
    out = run_chain(lines, verbose)
    final = [m for m in net_events(out, "eth1") if m.bucket == quiet_bucket]
    if not final:
        return ["the stale pass never flushed eth1's bucket %d; eth1 "
                "emitted %s" % (quiet_bucket,
                                sorted(m.bucket
                                       for m in net_events(out, "eth1")))]
    return []


def forward_step_lines(stale_batch):
    """cpu and net jump ten buckets. With <stale_batch> the tcp_stats
    batches spanning the jump still carry the pre-jump timestamp, which
    is what connstat does; without it they carry their own. Nothing
    else differs between the two."""
    gen = Gen()
    lines = []
    for i in range(2 * SAMPLES_PER_BUCKET):
        ts = BASE * BUCKET_NS + i * SAMPLE_NS
        lines.append(gen.cpu(ts))
        lines.append(gen.net("eth0", ts))
        lines.append(gen.tcp(TCP_KEY, ts))
    stale_ts = (BASE * BUCKET_NS
                + (2 * SAMPLES_PER_BUCKET - 1) * SAMPLE_NS)
    jumped = BASE + 10
    for i in range(3 * SAMPLES_PER_BUCKET):
        ts = jumped * BUCKET_NS + i * SAMPLE_NS
        lines.append(gen.cpu(ts))
        lines.append(gen.net("eth0", ts))
        if i < 2:
            lines.append(gen.tcp(TCP_KEY, stale_ts if stale_batch else ts))
    return lines, jumped


def case_forward_step_with_lagging_input(verbose):
    """A forward clock step with one input still behind.

    cpu and net jump ten buckets, one tcp_stats batch still carries the
    old timestamp. That batch must not read as a backward step: the net
    keys are live at the new time, and flushing them emits an empty
    event for a bucket still filling and drops the counter baselines
    the rest of that bucket is measured against. What the net keys
    report cannot depend on when a tcp_stats batch says it was taken,
    so the two runs below have to agree event for event.
    """
    lines, jumped = forward_step_lines(True)
    out = run_chain(lines, verbose)
    reference, _ = forward_step_lines(False)
    expected = run_chain(reference, False)
    failures = []
    seen = {}
    for m in net_events(out, "eth0"):
        seen[m.bucket] = seen.get(m.bucket, 0) + 1
        if m.bucket >= jumped and int(m.tags.get("data.inBytes", "0")) == 0:
            failures.append("eth0 emitted an empty event for bucket %d "
                            "while it was reporting" % m.bucket)
    for bucket in sorted(seen):
        if seen[bucket] > 1:
            failures.append("eth0 emitted bucket %d %d times"
                            % (bucket, seen[bucket]))

    def summary(events):
        return [(m.bucket, m.tags.get("data.inBytes"),
                 m.tags.get("data.outBytes")) for m in events]

    got = summary(net_events(out, "eth0"))
    want = summary(net_events(expected, "eth0"))
    if got != want:
        failures.append("the lagging batch moved eth0's events: %s, "
                        "against %s with the batch on time" % (got, want))
    return failures


CASES = [
    ("one input two buckets behind", case_lagging_input),
    ("key quiet before a backward step", case_quiet_before_retreat),
    ("stale pass after a backward step", case_stale_after_retreat),
    ("forward step with a lagging input",
     case_forward_step_with_lagging_input),
]


def main():
    verbose = "-v" in sys.argv[1:]
    if shutil.which("telegraf") is None:
        print("telegraf is not installed; these fixtures drive the real "
              "binary")
        return 2
    failed = 0
    for name, case in CASES:
        failures = case(verbose)
        if failures:
            failed += 1
            print("FAIL %s" % name)
            for line in failures:
                print("       %s" % line)
        else:
            print("PASS %s" % name)
    print("\n%d of %d cases passed" % (len(CASES) - failed, len(CASES)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
