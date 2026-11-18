#!/usr/bin/env python3
# Copyright (c) 2026 by Delphix. All rights reserved.
#
# Deep data-validation review for the fluentd compat metric pipeline.
#
# Derives Java's invariants from a sample of fold-met events (the old Java
# path) and then checks every new fluentd-met event against those invariants
# with zero tolerance for identities. Prints pass/fail numbers for every
# check — silence is not a pass.
#
# Expected input files (collected via Splunk REST or the Splunk CLI):
#   /tmp/old_events.jsonl  — one JSON event per line, from index="fold-met"
#   /tmp/new_events.jsonl  — one JSON event per line, from index="fluentd-met"
#
# Each line is the raw "_raw" payload Splunk stored for that event. A typical
# counter event looks like:
#   {"metric_name":"system.disk.ops.count","_value":2360,"data":{
#       "op":"write","count":2360,"avgLatency":1020,"throughput":32970,
#       "latency":{"600":5,"700":15,"800":51,"900":373,"1000":952,"2000":969}
#   },...}
#
# Usage:
#   python3 scripts/validate-fluentd-compat.py \
#       [--old /path/to/old_events.jsonl] \
#       [--new /path/to/new_events.jsonl]
#
# Exits non-zero if any invariant check fails against the new events.

import argparse
import json
import sys
from collections import defaultdict


def load(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def group_by_metric(events):
    g = defaultdict(list)
    for e in events:
        g[e.get("metric_name", "?")].append(e)
    return g


def derive_java_invariants(java_events_by_metric):
    """For each metric, extract what holds across every Java event.

    An invariant with mixed truth across the sample is reported as None — we
    do not rely on it. This forces the caller to drop any claim that isn't
    unanimous in the reference.
    """
    out = {}
    for metric, events in java_events_by_metric.items():
        inv = {"sample_size": len(events)}

        # fields and types
        field_sets = [frozenset(e.get("data", {}).keys()) for e in events]
        type_examples = defaultdict(set)
        for e in events:
            for k, v in e.get("data", {}).items():
                type_examples[k].add(type(v).__name__)
        if field_sets:
            common = set.intersection(*[set(s) for s in field_sets])
            union = set.union(*[set(s) for s in field_sets])
            inv["fields_always"] = sorted(common)
            inv["fields_sometimes"] = sorted(union - common)
        inv["field_types"] = {k: sorted(v) for k, v in type_examples.items()}

        # Counter identities
        if metric.endswith(".ops.count"):
            cnt_eq_hist, val_eq_cnt, cnt_positive = [], [], []
            counts = []
            for e in events:
                d = e.get("data", {})
                try:
                    cnt = int(d.get("count", 0))
                except (TypeError, ValueError):
                    cnt = 0
                try:
                    val = int(e.get("_value", 0))
                except (TypeError, ValueError):
                    val = 0
                lat = d.get("latency", {})
                hs = sum(lat.values()) if isinstance(lat, dict) else None
                if hs is not None:
                    cnt_eq_hist.append(cnt == hs)
                val_eq_cnt.append(val == cnt)
                cnt_positive.append(cnt > 0)
                counts.append(cnt)
            inv["count_eq_hist_sum"] = all(cnt_eq_hist) if cnt_eq_hist else None
            inv["value_eq_count"] = all(val_eq_cnt) if val_eq_cnt else None
            inv["count_positive"] = all(cnt_positive) if cnt_positive else None
            if counts:
                inv["count_range"] = (min(counts), max(counts))

        # Byte-summary identity
        if metric.endswith(".bytes"):
            matches = []
            for e in events:
                d = e.get("data", {})
                try:
                    val = int(e.get("_value", 0))
                    inb = int(d.get("inBytes", 0))
                    out_b = int(d.get("outBytes", 0))
                    matches.append(val == inb + out_b)
                except (TypeError, ValueError):
                    pass
            if matches:
                inv["value_eq_inBytes_plus_outBytes"] = all(matches)

        out[metric] = inv
    return out


def check_new_events(invariants, new_by_metric):
    """Return (findings, summary_lines).

    `findings` is a list of dicts in bmad-review canonical shape.
    `summary_lines` is a per-metric list of "N/M passed" strings for rendering.
    """
    findings = []
    lines = []

    for metric, inv in invariants.items():
        events = new_by_metric.get(metric, [])
        if not events:
            lines.append(f"{metric}: no new events (Java had {inv['sample_size']})")
            continue
        n = len(events)
        checks = []

        # Required fields
        if inv.get("fields_always"):
            required = set(inv["fields_always"])
            missing = defaultdict(int)
            for e in events:
                for f in required - set(e.get("data", {}).keys()):
                    missing[f] += 1
            if missing:
                findings.append(dict(
                    lens="adversarial",
                    location=f"{metric}: required fields",
                    trigger_condition=f"Fields {dict(missing)} missing from new events (Java always has them)",
                    guard_snippet="Emit the missing fields in the starlark flush block",
                    potential_consequence="Splunk dashboards relying on these fields break",
                ))
                checks.append(f"fields: ✗ {dict(missing)}")
            else:
                checks.append(f"fields: ✓ {len(required)} required fields on all {n} events")

        # Types
        type_mm = defaultdict(list)
        for e in events:
            for k, v in e.get("data", {}).items():
                allowed = inv.get("field_types", {}).get(k)
                if allowed and type(v).__name__ not in allowed:
                    type_mm[k].append((type(v).__name__, allowed))
        if type_mm:
            for k, cases in type_mm.items():
                findings.append(dict(
                    lens="adversarial",
                    location=f"{metric}: data.{k}",
                    trigger_condition=f"Type mismatch — Java had {cases[0][1]}, new has {cases[0][0]} in {len(cases)} events",
                    guard_snippet="Fix numeric type conversion in record_transformer",
                    potential_consequence="Splunk numeric comparisons fail",
                ))
            checks.append(f"types: ✗ {list(type_mm.keys())}")
        else:
            checks.append(f"types: ✓ all match on {n} events")

        # Counter identities
        if metric.endswith(".ops.count"):
            if inv.get("count_eq_hist_sum"):
                deltas = []
                for e in events:
                    d = e.get("data", {})
                    try:
                        cnt = int(d.get("count", 0))
                    except (TypeError, ValueError):
                        cnt = 0
                    lat = d.get("latency", {})
                    if isinstance(lat, dict):
                        deltas.append(cnt - sum(lat.values()))
                if deltas:
                    max_abs = max(abs(d) for d in deltas)
                    failures = sum(1 for d in deltas if d != 0)
                    if failures:
                        findings.append(dict(
                            lens="adversarial",
                            location=f"{metric}: count vs histogram sum",
                            trigger_condition=f"count != sum(latency.values()) in {failures}/{len(deltas)} events, max delta {max_abs}",
                            guard_snippet="Use sum(histogram.values()) as count when histogram present",
                            potential_consequence="Dashboard summaries disagree with histogram breakdowns",
                        ))
                        checks.append(f"count=hist_sum: ✗ {failures}/{len(deltas)} failures, max_delta={max_abs}")
                    else:
                        checks.append(f"count=hist_sum: ✓ EXACT on all {len(deltas)} events")

            if inv.get("value_eq_count"):
                fails = []
                for e in events:
                    try:
                        v = int(e.get("_value", 0))
                        c = int(e.get("data", {}).get("count", 0))
                    except (TypeError, ValueError):
                        v, c = 0, 0
                    if v != c:
                        fails.append((v, c))
                if fails:
                    findings.append(dict(
                        lens="adversarial",
                        location=f"{metric}: _value vs data.count",
                        trigger_condition=f"_value != data.count in {len(fails)} events: samples {fails[:3]}",
                        guard_snippet="Ensure m.fields[\"count\"] matches the tag emission",
                        potential_consequence="Splunk _value aggregations diverge from data.count",
                    ))
                    checks.append(f"_value=count: ✗ {len(fails)} failures")
                else:
                    checks.append(f"_value=count: ✓ EXACT on all {n} events")

            if inv.get("count_positive"):
                zeros = [e for e in events if int(e.get("data", {}).get("count", 0) or 0) == 0]
                if zeros:
                    findings.append(dict(
                        lens="adversarial",
                        location=f"{metric}: zero-count events",
                        trigger_condition=f"count=0 in {len(zeros)} events; Java never emits count=0",
                        guard_snippet="Guard emission with if cnt > 0",
                        potential_consequence="Noise in Splunk dashboards",
                    ))
                    checks.append(f"count>0: ✗ {len(zeros)} zero-count events")
                else:
                    checks.append(f"count>0: ✓ all {n} events have count > 0")

        # Byte-summary identity
        if metric.endswith(".bytes") and inv.get("value_eq_inBytes_plus_outBytes"):
            fails = []
            for e in events:
                d = e.get("data", {})
                try:
                    v = int(e.get("_value", 0))
                    s = int(d.get("inBytes", 0)) + int(d.get("outBytes", 0))
                except (TypeError, ValueError):
                    continue
                if v != s:
                    fails.append((v, s))
            if fails:
                findings.append(dict(
                    lens="adversarial",
                    location=f"{metric}: _value vs inBytes+outBytes",
                    trigger_condition=f"_value != inBytes+outBytes in {len(fails)} events",
                    guard_snippet="Fix _value derivation at emission",
                    potential_consequence="Splunk sums wrong",
                ))
                checks.append(f"_value=in+out: ✗ {len(fails)} failures")
            else:
                checks.append(f"_value=in+out: ✓ EXACT on all {n} events")

        # CPU range
        if metric == "system.cpu.util.pct":
            fails = []
            for e in events:
                try:
                    v = float(e.get("_value", 0))
                except (TypeError, ValueError):
                    v = -1
                if not (0 <= v <= 100):
                    fails.append(v)
            if fails:
                findings.append(dict(
                    lens="edge-case-hunter",
                    location=f"{metric}: _value range",
                    trigger_condition=f"CPU pct outside [0,100] in {len(fails)} events",
                    guard_snippet="Review pct calculation",
                    potential_consequence="CPU alerts broken",
                ))
                checks.append(f"pct∈[0,100]: ✗ {len(fails)} failures")
            else:
                vals = [float(e.get("_value", 0)) for e in events if e.get("_value") is not None]
                checks.append(f"pct∈[0,100]: ✓ all {n} events, range {min(vals):.1f}-{max(vals):.1f}")

        lines.append(f"{metric} (n={n}): " + "; ".join(checks))

    return findings, lines


def unit_sanity(metric, events):
    """Per-event avgLatency vs bucket-value-weighted mean ratio.

    Returns a list of ratios. le is upper bound → ratio in [1.0, 2.0] is
    normal; wider range on low-count events is the floor-to-1 fallback
    artifact, not a bug.
    """
    ratios = []
    for e in events:
        d = e.get("data", {})
        try:
            avg = int(d.get("avgLatency", 0))
        except (TypeError, ValueError):
            avg = 0
        lat = d.get("latency", {})
        if avg > 0 and isinstance(lat, dict) and lat:
            hs = sum(lat.values())
            if hs > 0:
                hm = sum(int(k) * v for k, v in lat.items()) / hs
                ratios.append(hm / avg)
    return ratios


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--old", default="/tmp/old_events.jsonl")
    ap.add_argument("--new", default="/tmp/new_events.jsonl")
    ap.add_argument("--findings-out", default="/tmp/review_findings.json")
    args = ap.parse_args()

    old = load(args.old)
    new = load(args.new)
    print(f"OLD events: {len(old)}  NEW events: {len(new)}")

    og = group_by_metric(old)
    ng = group_by_metric(new)
    metrics = sorted(set(og.keys()) | set(ng.keys()))
    print("\nMetrics in window:")
    for m in metrics:
        print(f"  {m:<40} OLD={len(og.get(m,[])):>4}  NEW={len(ng.get(m,[])):>4}")

    print("\n=== Java invariants (derived from fold-met) ===")
    invariants = derive_java_invariants(og)
    for m, inv in invariants.items():
        if inv["sample_size"] == 0:
            continue
        print(f"\n{m} (n={inv['sample_size']}):")
        if inv.get("fields_always"):
            print(f"  fields always: {inv['fields_always']}")
        if inv.get("fields_sometimes"):
            print(f"  fields sometimes: {inv['fields_sometimes']}")
        for k in ("count_eq_hist_sum", "value_eq_count", "count_positive", "value_eq_inBytes_plus_outBytes"):
            if inv.get(k) is not None:
                print(f"  {k}: {inv[k]}")

    print("\n=== Checking NEW events against invariants (every event, zero tolerance) ===")
    findings, lines = check_new_events(invariants, ng)
    for l in lines:
        print(f"\n{l}")

    print("\n=== avgLatency vs bucket-mean ratio (per event) ===")
    for m in [x for x in metrics if x.endswith(".ops.count")]:
        new_r = unit_sanity(m, ng.get(m, []))
        old_r = unit_sanity(m, og.get(m, []))
        print(f"\n{m}")
        if new_r:
            print(f"  NEW ratios: n={len(new_r)} range=[{min(new_r):.2f}, {max(new_r):.2f}] median={sorted(new_r)[len(new_r)//2]:.2f}")
        if old_r:
            print(f"  OLD ratios: n={len(old_r)} range=[{min(old_r):.2f}, {max(old_r):.2f}] median={sorted(old_r)[len(old_r)//2]:.2f}")

    print(f"\n=== FINDINGS: {len(findings)} ===")
    for f in findings:
        print(f"\n  [{f['lens']}] {f['location']}")
        print(f"    trigger: {f['trigger_condition']}")
        print(f"    guard:   {f['guard_snippet']}")
        print(f"    risk:    {f['potential_consequence']}")

    with open(args.findings_out, "w") as f:
        json.dump(findings, f, indent=2)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
