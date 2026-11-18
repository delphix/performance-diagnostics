#!/usr/bin/env python3
# Copyright (c) 2026 by Delphix. All rights reserved.
#
# Deep data-validation review for the fluentd compat metric pipeline.
#
# Earlier reviews with loose tolerances missed unit discrepancies (ns vs us,
# bytes vs kilobytes) that only a cross-check against real Java events can
# catch. R1-11 on PR #138 noted that an identity which the code enforces by
# construction (e.g. count == sum(histogram) when count IS sum(histogram))
# carries no evidence — the audit must compare against the reference, not
# against itself. This script does both:
#
#   1. Invariant check: derive invariants from Java (fold-met) and verify
#      every new (fluentd-met) event preserves them, with zero tolerance for
#      identities and the per-event max delta printed either way.
#
#   2. Unit cross-check: for same-metric same-op events in both indexes,
#      compare the magnitude of avgLatency, throughput, and latency histogram
#      bucket keys. A 1000x or 1024x divergence between indexes points to a
#      unit error (us vs ns, kB vs B) regardless of which side is right —
#      catches the class of defect that cannot be found by checking a path
#      against itself.
#
# Expected input files (collected via Splunk REST or the Splunk CLI):
#   /tmp/old_events.jsonl  — one JSON event per line, from index="fold-met"
#   /tmp/new_events.jsonl  — one JSON event per line, from index="fluentd-met"
#
# Each line is the raw "_raw" payload Splunk stored for that event.
#
# Usage:
#   python3 scripts/validate-fluentd-compat.py \
#       [--old /path/to/old_events.jsonl] \
#       [--new /path/to/new_events.jsonl]
#
# Exits non-zero if any invariant check fails against the new events, any unit
# cross-check flags a probable scaling error (ratio outside [0.1, 10]), or the
# run had nothing to check: an export that is empty, that holds lines the JSON
# parser could not read, or that is missing a metric the Java reference has.
# A run that checked nothing must not look like a clean one.

import argparse
import json
import statistics
import sys
from collections import defaultdict


# "Fields {missing} missing from new events" — Java-derived required set.
MISSING_FIELDS_TRIGGER = (
    "Fields {missing} missing from new events (Java always has them)"
)
MISSING_FIELDS_GUARD = (
    "Emit the missing fields in the starlark flush block"
)
MISSING_FIELDS_RISK = (
    "Splunk dashboards relying on these fields break"
)

TYPE_MISMATCH_GUARD = (
    "Fix numeric type conversion in record_transformer"
)
TYPE_MISMATCH_RISK = "Splunk numeric comparisons fail"

HIST_SUM_GUARD = (
    "Use sum(histogram.values()) as count when histogram present"
)
HIST_SUM_RISK = (
    "Dashboard summaries disagree with histogram breakdowns"
)

VALUE_COUNT_GUARD = (
    'Ensure m.fields["count"] matches the tag emission'
)
VALUE_COUNT_RISK = (
    "Splunk _value aggregations diverge from data.count"
)

NO_NEW_EVENTS_GUARD = (
    "Emit {metric} from the starlark flush block, or drop it from the "
    "reference window"
)
NO_NEW_EVENTS_RISK = (
    "A metric Java published is missing from Splunk entirely"
)

UNPARSED_GUARD = (
    "Re-collect the export; a truncated file or a Splunk error page "
    "reads as zero events"
)
UNPARSED_RISK = "An audit that read nothing reports a clean run"

NO_EVENTS_GUARD = (
    "Check the Splunk query window and the index name"
)
NO_EVENTS_RISK = "An audit that compared nothing reports a clean run"

SCALE_FIELD_GUARD = (
    "Verify units match delphix.json for {field} (us vs ns, kB vs B)"
)
SCALE_FIELD_RISK = (
    "Latency alerts, throughput dashboards off by orders of magnitude"
)

OP_SCALE_GUARD = (
    "Verify units for {field} match delphix.json "
    "(avgLatency ns, throughput bytes)"
)
OP_SCALE_RISK = (
    "Latency alerts and throughput dashboards off by orders of magnitude"
)

HIST_SCALE_GUARD = (
    "Verify histogram le keys match Java's (nanoseconds per delphix.json)"
)
HIST_SCALE_RISK = (
    "Latency distribution dashboards show the wrong scale"
)


def load(path):
    """Return (events, count of lines that were not JSON).

    A truncated export or a Splunk error page produces lines the parser
    cannot read. Dropping them silently is how a run that read nothing comes
    out looking like a clean one, so the caller gets the count and reports it.
    """
    out = []
    unparsed = 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                unparsed += 1
    return out, unparsed


def as_number(value):
    """Return value as a float, or None when it is not a number.

    A field that cannot be read as a number is a defect in its own right, so
    every caller reports it instead of substituting zero and comparing two
    zeros. bool is excluded because Python counts it as an int.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


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
            inv["count_eq_hist_sum"] = (
                all(cnt_eq_hist) if cnt_eq_hist else None
            )
            inv["value_eq_count"] = (
                all(val_eq_cnt) if val_eq_cnt else None
            )
            inv["count_positive"] = (
                all(cnt_positive) if cnt_positive else None
            )
            if counts:
                inv["count_range"] = (min(counts), max(counts))

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


def _check_required_fields(metric, inv, events, findings, checks):
    required = set(inv["fields_always"])
    missing = defaultdict(int)
    for e in events:
        for f in required - set(e.get("data", {}).keys()):
            missing[f] += 1
    if missing:
        findings.append(dict(
            lens="adversarial",
            location=f"{metric}: required fields",
            trigger_condition=MISSING_FIELDS_TRIGGER.format(
                missing=dict(missing)),
            guard_snippet=MISSING_FIELDS_GUARD,
            potential_consequence=MISSING_FIELDS_RISK,
        ))
        checks.append(f"fields: FAIL {dict(missing)}")
    else:
        checks.append(
            f"fields: OK {len(required)} required on all {len(events)}"
        )


def _check_types(metric, inv, events, findings, checks):
    type_mm = defaultdict(list)
    for e in events:
        for k, v in e.get("data", {}).items():
            allowed = inv.get("field_types", {}).get(k)
            if allowed and type(v).__name__ not in allowed:
                type_mm[k].append((type(v).__name__, allowed))
    if type_mm:
        for k, cases in type_mm.items():
            got, want = cases[0][0], cases[0][1]
            findings.append(dict(
                lens="adversarial",
                location=f"{metric}: data.{k}",
                trigger_condition=(
                    f"Type mismatch — Java had {want}, "
                    f"new has {got} in {len(cases)} events"
                ),
                guard_snippet=TYPE_MISMATCH_GUARD,
                potential_consequence=TYPE_MISMATCH_RISK,
            ))
        checks.append(f"types: FAIL {list(type_mm.keys())}")
    else:
        checks.append(f"types: OK all match on {len(events)} events")


def _check_count_hist_sum(metric, events, findings, checks):
    deltas = []
    unreadable = 0
    for e in events:
        d = e.get("data", {})
        lat = d.get("latency", {})
        if not isinstance(lat, dict):
            continue
        cnt = as_number(d.get("count"))
        hist = [as_number(v) for v in lat.values()]
        if cnt is None or None in hist:
            unreadable += 1
            continue
        deltas.append(cnt - sum(hist))
    if not deltas and not unreadable:
        return
    max_abs = max([abs(d) for d in deltas] or [0])
    failures = sum(1 for d in deltas if d != 0) + unreadable
    if failures:
        findings.append(dict(
            lens="adversarial",
            location=f"{metric}: count vs histogram sum",
            trigger_condition=(
                f"count != sum(latency.values()) in "
                f"{failures}/{len(deltas) + unreadable} events "
                f"({unreadable} unreadable), max delta {max_abs}"
            ),
            guard_snippet=HIST_SUM_GUARD,
            potential_consequence=HIST_SUM_RISK,
        ))
        checks.append(
            f"count=hist_sum: FAIL {failures}/{len(deltas) + unreadable}, "
            f"max_delta={max_abs}"
        )
    else:
        checks.append(f"count=hist_sum: EXACT on all {len(deltas)} events")


def _check_value_eq_count(metric, events, findings, checks):
    fails = []
    for e in events:
        raw_v = e.get("_value")
        raw_c = e.get("data", {}).get("count")
        v = as_number(raw_v)
        c = as_number(raw_c)
        if v is None or c is None or v != c:
            fails.append((raw_v, raw_c))
    if fails:
        findings.append(dict(
            lens="adversarial",
            location=f"{metric}: _value vs data.count",
            trigger_condition=(
                f"_value != data.count, or either is not a number, in "
                f"{len(fails)} events: samples {fails[:3]}"
            ),
            guard_snippet=VALUE_COUNT_GUARD,
            potential_consequence=VALUE_COUNT_RISK,
        ))
        checks.append(f"_value=count: FAIL {len(fails)} events")
    else:
        checks.append(f"_value=count: EXACT on all {len(events)} events")


def _check_count_positive(metric, events, findings, checks):
    bad = []
    for e in events:
        raw = e.get("data", {}).get("count")
        cnt = as_number(raw)
        if cnt is None or cnt <= 0:
            bad.append(raw)
    if bad:
        findings.append(dict(
            lens="adversarial",
            location=f"{metric}: non-positive count",
            trigger_condition=(
                f"count is not a positive number in {len(bad)} events: "
                f"samples {bad[:3]}; Java only emits an event for an "
                "op it counted"
            ),
            guard_snippet="Guard emission with if cnt > 0",
            potential_consequence="Noise in Splunk dashboards",
        ))
        checks.append(f"count>0: FAIL {len(bad)} events")
    else:
        checks.append(
            f"count>0: OK all {len(events)} events have count > 0"
        )


def _check_bytes_sum(metric, events, findings, checks):
    fails = []
    for e in events:
        d = e.get("data", {})
        v = as_number(e.get("_value"))
        inb = as_number(d.get("inBytes"))
        outb = as_number(d.get("outBytes"))
        if v is None or inb is None or outb is None or v != inb + outb:
            fails.append(
                (e.get("_value"), d.get("inBytes"), d.get("outBytes")))
    if fails:
        findings.append(dict(
            lens="adversarial",
            location=f"{metric}: _value vs inBytes+outBytes",
            trigger_condition=(
                f"_value != inBytes+outBytes, or one of them is not a "
                f"number, in {len(fails)} events: samples {fails[:3]}"
            ),
            guard_snippet="Fix _value derivation at emission",
            potential_consequence="Splunk sums wrong",
        ))
        checks.append(f"_value=in+out: FAIL {len(fails)} events")
    else:
        checks.append(f"_value=in+out: EXACT on all {len(events)} events")


def _check_cpu_range(metric, events, findings, checks):
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
            trigger_condition=(
                f"CPU pct outside [0,100] in {len(fails)} events"
            ),
            guard_snippet="Review pct calculation",
            potential_consequence="CPU alerts broken",
        ))
        checks.append(f"pct_in_0_100: FAIL {len(fails)} events")
    else:
        vals = [
            float(e.get("_value", 0))
            for e in events
            if e.get("_value") is not None
        ]
        checks.append(
            f"pct_in_0_100: OK all {len(events)} events, "
            f"range {min(vals):.1f}-{max(vals):.1f}"
        )


def check_new_events(invariants, new_by_metric):
    """Per-event invariant check with zero tolerance for identities.

    Prints the pass/fail count and max delta for every check — silence is
    not a pass.
    """
    findings = []
    lines = []

    for metric, inv in invariants.items():
        events = new_by_metric.get(metric, [])
        if not events:
            findings.append(dict(
                lens="adversarial",
                location=f"{metric}: no new events",
                trigger_condition=(
                    f"Java published {inv['sample_size']} events for "
                    f"{metric} in this window; the new path published none"
                ),
                guard_snippet=NO_NEW_EVENTS_GUARD.format(metric=metric),
                potential_consequence=NO_NEW_EVENTS_RISK,
            ))
            lines.append(
                f"{metric}: FAIL no new events "
                f"(Java had {inv['sample_size']})"
            )
            continue
        checks = []

        if inv.get("fields_always"):
            _check_required_fields(metric, inv, events, findings, checks)

        _check_types(metric, inv, events, findings, checks)

        if metric.endswith(".ops.count"):
            if inv.get("count_eq_hist_sum"):
                _check_count_hist_sum(metric, events, findings, checks)
            if inv.get("value_eq_count"):
                _check_value_eq_count(metric, events, findings, checks)
            if inv.get("count_positive"):
                _check_count_positive(metric, events, findings, checks)

        if metric.endswith(".bytes") and inv.get(
                "value_eq_inBytes_plus_outBytes"):
            _check_bytes_sum(metric, events, findings, checks)

        if metric == "system.cpu.util.pct":
            _check_cpu_range(metric, events, findings, checks)

        lines.append(
            f"{metric} (n={len(events)}): " + "; ".join(checks)
        )

    return findings, lines


# ---------------------------------------------------------------------------
# UNIT CROSS-CHECK
# ---------------------------------------------------------------------------
#
# The single most dangerous class of defect for this pipeline is a unit
# error: emitting microseconds where Java sent nanoseconds, or kilobytes
# where Java sent bytes. These cannot be caught by checking the new path
# against itself; the only signal is magnitude disagreement with the
# reference.
#
# For each (metric, op) pair with events in both indexes, compare the
# medians of the numeric fields that both carry. A median ratio that falls
# well outside [0.1, 10] on a scale-sensitive field (latency / throughput /
# histogram bucket keys) is almost certainly a scaling defect.
#
# This check is deliberately coarse. A 10x gap between a median NFS write
# latency on an idle test engine and a production Java engine is expected
# — a 1000x gap is not. The ratio bounds catch the ns/us and kB/B class of
# defect without crying wolf on workload differences.
# ---------------------------------------------------------------------------

SCALE_RATIO_FLOOR = 0.1
SCALE_RATIO_CEILING = 10.0


def _scale_trigger(ratio):
    return (
        f"NEW/OLD median ratio {ratio:.4f} outside "
        f"[{SCALE_RATIO_FLOOR},{SCALE_RATIO_CEILING}] — "
        "probable unit mismatch"
    )


def _scale_check_field(metric, field, old_events, new_events,
                       findings, lines):
    old_vals = _collect_field(old_events, field)
    new_vals = _collect_field(new_events, field)
    if not old_vals or not new_vals:
        lines.append(
            f"  {field}: skip "
            f"(old n={len(old_vals)}, new n={len(new_vals)})"
        )
        return
    ro = statistics.median(old_vals)
    rn = statistics.median(new_vals)
    if ro == 0 or rn == 0:
        lines.append(
            f"  {field}: skip (median is zero: old={ro}, new={rn})"
        )
        return
    ratio = rn / ro
    verdict = _scale_verdict(ratio)
    lines.append(
        f"  {field}: OLD median={ro:.1f}, NEW median={rn:.1f}, "
        f"ratio={ratio:.3f} ({verdict})"
    )
    if verdict == "FAIL":
        findings.append(dict(
            lens="adversarial",
            location=f"{metric}: data.{field}",
            trigger_condition=_scale_trigger(ratio),
            guard_snippet=SCALE_FIELD_GUARD.format(field=field),
            potential_consequence=SCALE_FIELD_RISK,
        ))


def _scale_check_op_field(metric, op, field, old_events, new_events,
                          findings, lines):
    old_vals = _collect_field(old_events, field)
    new_vals = _collect_field(new_events, field)
    if not old_vals or not new_vals:
        return
    ro = statistics.median(old_vals)
    rn = statistics.median(new_vals)
    if ro == 0 or rn == 0:
        return
    ratio = rn / ro
    verdict = _scale_verdict(ratio)
    lines.append(
        f"  op={op} {field}: OLD median={ro:.1f}, "
        f"NEW median={rn:.1f}, ratio={ratio:.3f} ({verdict})"
    )
    if verdict == "FAIL":
        findings.append(dict(
            lens="adversarial",
            location=f"{metric} op={op}: data.{field}",
            trigger_condition=_scale_trigger(ratio),
            guard_snippet=OP_SCALE_GUARD.format(field=field),
            potential_consequence=OP_SCALE_RISK,
        ))


def _scale_check_hist(metric, op, old_events, new_events, findings, lines):
    old_bkts = _collect_hist_keys(old_events)
    new_bkts = _collect_hist_keys(new_events)
    if not (old_bkts and new_bkts):
        return
    ro = statistics.median(old_bkts)
    rn = statistics.median(new_bkts)
    if ro == 0 or rn == 0:
        return
    ratio = rn / ro
    verdict = _scale_verdict(ratio)
    lines.append(
        f"  op={op} latency bucket keys: "
        f"OLD median={ro:.0f}, NEW median={rn:.0f}, "
        f"ratio={ratio:.3f} ({verdict})"
    )
    if verdict == "FAIL":
        findings.append(dict(
            lens="adversarial",
            location=f"{metric} op={op}: data.latency bucket keys",
            trigger_condition=_scale_trigger(ratio),
            guard_snippet=HIST_SCALE_GUARD,
            potential_consequence=HIST_SCALE_RISK,
        ))


def unit_cross_check(old_by_metric, new_by_metric):
    """Compare median magnitudes of scale-sensitive fields across indexes.

    Returns (findings, lines).
    """
    findings = []
    lines = []

    shared = sorted(
        set(old_by_metric.keys()) & set(new_by_metric.keys())
    )
    for metric in shared:
        if not metric.endswith(".ops.count"):
            scale_fields = _scale_fields_for(metric)
            if not scale_fields:
                continue
            lines.append(f"\n{metric}")
            for field in scale_fields:
                _scale_check_field(
                    metric, field,
                    old_by_metric[metric], new_by_metric[metric],
                    findings, lines,
                )
            continue

        old_by_op = _split_by_op(old_by_metric[metric])
        new_by_op = _split_by_op(new_by_metric[metric])
        ops = sorted(set(old_by_op.keys()) & set(new_by_op.keys()))
        lines.append(f"\n{metric}")
        for op in ops:
            for field in ("avgLatency", "throughput"):
                _scale_check_op_field(
                    metric, op, field,
                    old_by_op[op], new_by_op[op],
                    findings, lines,
                )
            _scale_check_hist(
                metric, op,
                old_by_op[op], new_by_op[op],
                findings, lines,
            )

    return findings, lines


# The six instantaneous gauges on system.tcp.total.bytes carry a scale of
# their own, independent of inBytes/outBytes: Java's minute datapoint sums its
# one-second per-connection means. They need the same magnitude comparison the
# latency and throughput fields get.
TCP_GAUGE_FIELDS = [
    "unacknowledgedBytes",
    "unsentBytes",
    "sendWindowSize",
    "congestionWindowSize",
    "receiveWindowSize",
    "roundTripTime",
]


def _scale_fields_for(metric):
    if metric == "system.tcp.total.bytes":
        return ["inBytes", "outBytes"] + TCP_GAUGE_FIELDS
    if metric.endswith(".bytes"):
        return ["inBytes", "outBytes"]
    return []


def _collect_field(events, field):
    out = []
    for e in events:
        v = e.get("data", {}).get(field)
        try:
            if v is not None:
                out.append(float(v))
        except (TypeError, ValueError):
            pass
    return out


def _split_by_op(events):
    out = defaultdict(list)
    for e in events:
        op = e.get("data", {}).get("op")
        if op:
            out[op].append(e)
    return out


def _collect_hist_keys(events):
    out = []
    for e in events:
        lat = e.get("data", {}).get("latency")
        if isinstance(lat, dict):
            for k in lat.keys():
                try:
                    out.append(int(k))
                except (TypeError, ValueError):
                    pass
    return out


def _scale_verdict(ratio):
    if SCALE_RATIO_FLOOR <= ratio <= SCALE_RATIO_CEILING:
        return "OK"
    return "FAIL"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--old", default="/tmp/old_events.jsonl")
    ap.add_argument("--new", default="/tmp/new_events.jsonl")
    ap.add_argument("--findings-out", default="/tmp/review_findings.json")
    args = ap.parse_args()

    old, old_unparsed = load(args.old)
    new, new_unparsed = load(args.new)
    print(
        f"OLD events: {len(old)} ({old_unparsed} unparseable)  "
        f"NEW events: {len(new)} ({new_unparsed} unparseable)"
    )

    input_findings = []
    for label, path, events, unparsed in (
        ("OLD (fold-met)", args.old, old, old_unparsed),
        ("NEW (fluentd-met)", args.new, new, new_unparsed),
    ):
        if unparsed:
            input_findings.append(dict(
                lens="adversarial",
                location=f"{label}: {path}",
                trigger_condition=(
                    f"{unparsed} lines could not be parsed as JSON"
                ),
                guard_snippet=UNPARSED_GUARD,
                potential_consequence=UNPARSED_RISK,
            ))
        if not events:
            input_findings.append(dict(
                lens="adversarial",
                location=f"{label}: {path}",
                trigger_condition="No events to compare",
                guard_snippet=NO_EVENTS_GUARD,
                potential_consequence=NO_EVENTS_RISK,
            ))

    og = group_by_metric(old)
    ng = group_by_metric(new)
    metrics = sorted(set(og.keys()) | set(ng.keys()))
    print("\nMetrics in window:")
    for m in metrics:
        print(
            f"  {m:<40} "
            f"OLD={len(og.get(m, [])):>4}  "
            f"NEW={len(ng.get(m, [])):>4}"
        )

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
        for k in (
            "count_eq_hist_sum",
            "value_eq_count",
            "count_positive",
            "value_eq_inBytes_plus_outBytes",
        ):
            if inv.get(k) is not None:
                print(f"  {k}: {inv[k]}")

    print("\n=== Invariant check (every new event, zero tolerance) ===")
    inv_findings, inv_lines = check_new_events(invariants, ng)
    for line in inv_lines:
        print(f"\n{line}")

    print("\n=== Unit cross-check (OLD vs NEW median magnitudes) ===")
    unit_findings, unit_lines = unit_cross_check(og, ng)
    for line in unit_lines:
        print(line)

    findings = input_findings + inv_findings + unit_findings
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
