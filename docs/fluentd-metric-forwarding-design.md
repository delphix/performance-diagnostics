# Telegraf → Fluentd Metric Forwarding — Design Document

**Status**: Draft — pending design review  
**Jira**: [DLPX-100030](https://perforce.atlassian.net/browse/DLPX-100030)  
**Author**: Dhruvin Shah  
**Reviewers**: Seb Roy (architecture), TBD

---

## 1. Executive Summary

Delphix engines can forward performance metrics to customer-managed monitoring systems (Splunk, Datadog, Elasticsearch) via a Fluentd HTTP routing layer. This path was previously implemented in Java (`pushInsightMetric`).

**Critical context:** When a Delphix Engine (DE) is added to DCT, Java performance collection is intentionally disabled on the engine to avoid data duplication (DCT becomes the collector). This means **customers who add their engine to DCT and rely on Splunk/Datadog forwarding immediately lose all metric data** — the Java path stops and there is currently no replacement. The Telegraf → Fluentd path is therefore not a refactor; it is a bug fix for an existing regression.

This document covers the High-Level Design (HLD) and Low-Level Design (LLD) for the Telegraf-based replacement, the risks, the stop-gap position, and the acceptance criteria for a production release.

---

## 2. Background — Why This Matters

### 2.1 The Problem: DCT Breaks Third-Party Metric Forwarding

When a DE is registered with DCT, the engine's Java analytics collection (`AnalyticsStorageImpl`, `LocalCpuCollector`, etc.) is disabled. This is intentional — DCT takes over and deduplicates the data. **However, `pushInsightMetric` — which forwards metrics to customer Splunk/Datadog — is also stopped as a side effect.**

```mermaid
graph LR
    subgraph Standalone["DE (standalone) — WORKS"]
        J1["Java analytics\n(running)"] --> F1["FluentD"] --> M1["Splunk / Datadog\n✅ data flowing"]
    end

    subgraph DCT["DE + DCT — BROKEN TODAY"]
        J2["Java analytics\n(disabled — dedup)"] -. stopped .-> F2["FluentD"] --> M2["Splunk / Datadog\n❌ no data"]
        T2["Telegraf\n(running — feeds DCT)"] -. no fluentd path .-> F2
    end
```

**Impact**: Any customer who has:
1. Enabled third-party metric forwarding (Splunk/Datadog), AND
2. Registered their engine with DCT

is currently receiving zero metric data in their monitoring system. This is a silent regression — Telegraf runs fine but has no path to Fluentd.

### 2.2 Why Replace It — The Real Driver Is DCT

The primary motivation is **not** decommissioning Java for its own sake. It is:

> When a DE is added to DCT, Java performance collection is intentionally stopped to prevent duplicate data. As a side effect, third-party metric forwarding (`pushInsightMetric`) also stops. Telegraf is already running on DCT-managed engines and is the only active collector — so Telegraf must take over the Fluentd forwarding role or those customers lose their Splunk/Datadog metrics entirely.

Secondary benefits (valid, but not the driver):
- One collection stack instead of two (lower maintenance)
- Richer granularity in InfluxDB from Telegraf
- Pluggable output architecture

### 2.3 The Current (Java) Path — Standalone Engines Only

For engines NOT registered with DCT, the Java path still works. Customers receive one metric event per minute for six engine-level KPIs:

```
Java (AnalyticsStorageImpl)
    │
    │  pushInsightMetric() — once per minute per metric
    │  format: flat JSON over FluentD Forward Protocol (TCP 24224)
    ▼
FluentD (on engine)
    │
    │  <match delphix.metrics.**>
    │  routes to customer plugin
    ▼
Customer Monitoring System (Splunk, Datadog, etc.)
```

**Event shape Java sends:**

```json
{
  "metric_name": "system.cpu.util.pct",
  "_value": 80.4,
  "_time": 1642520280000,
  "event": "metric",
  "type": "g",
  "systemUniqueId": "564dec8e-f543-1aeb-7563-ee08901877c5",
  "systemVersion": "6.0.1.0",
  "data": { "user": 360, "kernel": 630, "idle": 118220 }
}
```

**The six Java metrics:**

| metric_name | Meaning | Unit |
|---|---|---|
| `system.cpu.util.pct` | CPU busy % in last minute | gauge, % |
| `system.net.total.bytes` | Network bytes (in+out) in last minute | counter, bytes |
| `system.disk.ops.count` | Disk ops (read+write) in last minute | counter, ops |
| `system.nfs.ops.count` | NFS ops (read+write) in last minute | counter, ops |
| `system.iscsi.ops.count` | iSCSI ops (read+write) in last minute | counter, ops |
| `system.tcp.total.bytes` | TCP bytes (in+out) in last minute | counter, bytes |

### 2.2 Why Replace It

Java's collection stack (`AnalyticsStorageImpl`, `LocalCpuCollector`, etc.) is being decommissioned as Telegraf becomes the single source of truth for engine metrics. The Telegraf path offers:
- Lower maintenance cost (one collection stack, not two)
- Richer metric granularity in InfluxDB
- Pluggable output architecture

---

## 3. High-Level Design (HLD)

### 3.1 Architecture Overview

```mermaid
graph TB
    subgraph Engine["Delphix Engine"]
        subgraph Inputs["Metric Collection (Telegraf inputs)"]
            CPU["inputs.cpu\n10s interval"]
            NET["inputs.net\n10s interval"]
            DISK["inputs.diskio\n60s interval"]
            NFS["inputs.execd\n(estat nfs)\n10s interval"]
            ISCSI["inputs.execd\n(estat iscsi)\n10s interval"]
            TCP["inputs.execd\n(connstat)\n10s interval"]
        end

        subgraph Processing["Metric Transform (processors.starlark)"]
            PROC["telegraf.processors.fluentd\n\n• Remap metric names to Java names\n• Compute deltas from cumulative counters\n• Roll up into 60s buckets\n• Inject engine identity tags\n\nOnly active when FLUENTD_ENABLED flag exists"]
        end

        subgraph Outputs["Outputs"]
            INFLUX["outputs.influxdb_v2\n(all raw metrics at full resolution)"]
            HTTP["outputs.http\n→ localhost:9880\n(only system.* compat metrics,\none per minute)"]
        end

        FLUENTD["FluentD\nHTTP source :9880\n\n<match delphix.metrics.**>"]
        FLAG["/etc/telegraf/\nFLUENTD_ENABLED\n(flag file)"]
        CLI["perf_fluentd\nenable | disable | status"]
    end

    subgraph Customer["Customer Monitoring"]
        SPLUNK["Splunk\n(mstats / SPL)"]
        DATADOG["Datadog"]
        ELASTIC["Elasticsearch"]
    end

    CPU & NET & DISK & NFS & ISCSI & TCP --> PROC
    CPU & NET & DISK & NFS & ISCSI & TCP --> INFLUX
    PROC --> HTTP
    HTTP --> FLUENTD
    FLAG -.controls.-> PROC
    CLI -.manages.-> FLAG
    FLUENTD --> SPLUNK & DATADOG & ELASTIC
```

### 3.2 User Control Flow

The customer or Delphix admin enables/disables forwarding via the setup screen. The app-gate calls `perf_fluentd enable/disable`. Telegraf restarts and re-reads the flag on every restart.

```mermaid
sequenceDiagram
    actor Admin as Admin / Setup Screen
    participant AppGate as dlpx-app-gate
    participant CLI as perf_fluentd
    participant Flag as /etc/telegraf/FLUENTD_ENABLED
    participant Service as delphix-telegraf-service
    participant Telegraf as telegraf (process)

    Admin->>AppGate: Save third-party credentials
    AppGate->>CLI: perf_fluentd enable
    CLI->>Flag: touch (create flag file)
    CLI->>Service: systemctl restart delphix-telegraf
    Service->>Service: Read flag → include processor + output
    Service->>Telegraf: Start with fluentd stanza in telegraf.conf

    Admin->>AppGate: Remove third-party credentials
    AppGate->>CLI: perf_fluentd disable
    CLI->>Flag: rm (remove flag file)
    CLI->>Service: systemctl restart delphix-telegraf
    Service->>Service: Flag absent → exclude processor + output
    Service->>Telegraf: Start without fluentd stanza
```

### 3.3 telegraf.conf Assembly

On every service start, `delphix-telegraf-service` generates `/etc/telegraf/telegraf.conf` by concatenating config fragments conditionally:

```mermaid
flowchart TD
    Start([Service starts]) --> Base[cat telegraf.base → telegraf.conf]
    Base --> StorIO{InfluxDB OR\nFluentD enabled?}
    StorIO -->|Yes| SI[append telegraf.inputs.storage_io\nest_nfs, estat_iscsi, tcp_stats]
    StorIO -->|No| InfluxQ

    SI --> InfluxQ{INFLUXDB_ENABLED?}
    InfluxQ -->|Yes + file exists| InfluxOut[append telegraf.outputs.influxdb]
    InfluxQ -->|Yes + file missing| InfluxWarn[logger WARNING]
    InfluxQ -->|No| FluentQ

    InfluxOut --> FluentQ
    InfluxWarn --> FluentQ

    FluentQ{FLUENTD_ENABLED?}
    FluentQ -->|Yes + output exists| ProcQ{FLUENTD_PROCESSOR\nexists?}
    FluentQ -->|Yes + output missing| FluentWarn[logger WARNING]
    FluentQ -->|No| HasOut

    ProcQ -->|Yes| Proc["envsubst UUID/VERSION\nappend telegraf.processors.fluentd"]
    ProcQ -->|No| ProcErr[logger ERROR\nraw names will be forwarded]

    Proc --> FluentOut[append telegraf.outputs.fluentd]
    ProcErr --> FluentOut
    FluentOut --> HasOut

    HasOut{has_output\n= true?}
    HasOut -->|No| Discard[echo outputs.discard]
    HasOut -->|Yes| Perms

    Discard --> Perms[chmod 640 telegraf.conf]
    Perms --> Launch[exec telegraf -config telegraf.conf]
```

---

## 4. Low-Level Design (LLD)

### 4.1 Files Shipped by This Feature

| File | Installed path | Purpose |
|---|---|---|
| `telegraf/perf_fluentd` | `/usr/bin/perf_fluentd` | Enable / disable / status CLI |
| `telegraf/telegraf.outputs.fluentd` | `/etc/telegraf/telegraf.outputs.fluentd` | HTTP output stanza (static) |
| `telegraf/telegraf.processors.fluentd` | `/etc/telegraf/telegraf.processors.fluentd` | Starlark metric transform |
| `telegraf/delphix-telegraf-service` | `/usr/bin/delphix-telegraf-service` | Modified: fluentd awareness |

### 4.2 Metric Transform Pipeline (Starlark Processor)

The starlark processor handles two classes of metrics differently:

#### Class A — Gauge (instantaneous value)

Only `system.cpu.util.pct`. Java computed `(user + kernel) / (user + kernel + idle) * 100` using delta jiffies over the sampling interval. Telegraf's `inputs.cpu` `usage_idle` field is already this ratio. We just invert it.

```
cpu (usage_idle = 5.3%)
    └─ system.cpu.util.pct = 100 - 5.3 = 94.7%
```

Bucketing: keep the last sample in each 60s window and emit once at bucket transition.

#### Class B — Counter (delta over the minute)

Java polled `/proc/net/dev`, `/proc/diskstats`, etc. and sent `current - previous`. Telegraf exposes the same data as cumulative counters. We compute the delta in starlark using persistent state.

```
net (bytes_recv=1000, bytes_sent=500)    ← cumulative since boot
    prev bytes_recv=800, bytes_sent=350   ← stored in state
    delta = (1000-800) + (500-350) = 350 bytes
    └─ system.net.total.bytes += 350       ← add to 60s bucket
```

At bucket boundary: emit the accumulated bucket total, reset to 0.

#### Class C — Rate-based counter (estat)

`estat nfs/iscsi` output `iops(/s)` — the average rate over the 10s collection window. To get ops-in-window: `iops * 10`. Two rows per window (name=read, name=write), both accumulated.

```
estat_nfs (iops(/s)=50, name=read)   → ops in 10s = 500
estat_nfs (iops(/s)=30, name=write)  → ops in 10s = 300
    accumulated into 60s bucket
    └─ system.nfs.ops.count = 800 total ops this minute
```

#### Bucket state machine (all counter types)

```mermaid
stateDiagram-v2
    [*] --> Waiting: Service starts
    Waiting --> Accumulating: First sample arrives\n(no previous baseline, delta=0)

    Accumulating --> Accumulating: Sample in same 60s bucket\nadd delta to bucket_acc

    Accumulating --> Emitting: First sample of NEW 60s bucket arrives
    Emitting --> Accumulating: Emit previous bucket total\nReset bucket_acc = 0\nAccumulate current sample

    note right of Waiting: state[*] = empty\nFirst delta always = 0\n(no prior baseline)
    note right of Emitting: Emitted metric goes to\noutputs.http → fluentd
```

### 4.3 Event Format (LLD — what actually flows over the wire)

Telegraf serialises using `splunkmetric_hec_routing = true`. For each field in each compat measurement, it emits one JSON object in Splunk HEC metrics format:

**Wire format (HTTP POST body — newline-delimited HEC events):**

```json
{"time":1793166060,"event":"metric","host":"ip-10-110-245-219","fields":{"metric_name":"system.cpu.util.pct","_value":94.7,"systemUniqueId":"564dec8e-...","systemVersion":"6.0.1.0"}}
{"time":1793166060,"event":"metric","host":"ip-10-110-245-219","fields":{"metric_name":"system.net.total.bytes","_value":350000,"systemUniqueId":"564dec8e-...","systemVersion":"6.0.1.0"}}
...
```

**Field-by-field comparison with Java:**

| Field | Java | Telegraf (this design) | Compatible? |
|---|---|---|---|
| `metric_name` | `system.cpu.util.pct` | `system.cpu.util.pct` | ✅ exact match |
| `_value` | numeric | numeric (delta-based, same semantics) | ✅ |
| `_time` / `time` | milliseconds epoch | seconds epoch (HEC standard) | ⚠️ unit differs |
| `event` | `"metric"` | `"metric"` | ✅ exact match |
| `systemUniqueId` | engine UUID | engine UUID (via `get-system-uuid`) | ✅ exact match |
| `systemVersion` | `"6.0.1.0"` | full build string | ⚠️ format differs |
| `type` | `"g"` / `"c"` | absent | ⚠️ missing |
| `data` | `{"user":360, ...}` | absent | ❌ not replicated |
| Structure | flat JSON object | HEC nested `{"fields":{...}}` | ⚠️ needs `data_type metric` in fluent-plugin-splunk-hec |

**Open items requiring design approval:**
1. `_time` unit — does fluent-plugin-splunk-hec accept seconds? Does Splunk mstats tolerate it?
2. `systemVersion` format — full build string vs. short version (`6.0.1.0`)?
3. `type` field — needed by any customer plugin?
4. `data` sub-object — any customer dashboard queries it?
5. Nested HEC structure — does the companion app-gate change (PR #5043) handle this?

### 4.4 Identity Tag Injection

`systemUniqueId` and `systemVersion` are set per compat metric inside the starlark source at config-generation time via `envsubst`. This scopes them to fluentd-bound metrics only (InfluxDB cardinality is unaffected).

```
delphix-telegraf-service
    ├── reads env: DELPHIX_SYSTEM_UUID=$(get-system-uuid)
    ├── reads env: DELPHIX_SYSTEM_VERSION=$(get-appliance-version)
    └── envsubst '${DELPHIX_SYSTEM_UUID} ${DELPHIX_SYSTEM_VERSION}' \
            < telegraf.processors.fluentd >> telegraf.conf
```

### 4.5 Enable / Disable Control

```mermaid
flowchart LR
    subgraph perf_fluentd
        E[enable]
        D[disable]
        S[status]
    end

    E -->|idempotent:\nalready enabled?| NoOp1[print msg, exit 0]
    E -->|not enabled| Touch["touch /etc/telegraf/FLUENTD_ENABLED\nrestart delphix-telegraf"]

    D -->|idempotent:\nalready disabled?| NoOp2[print msg, exit 0]
    D -->|enabled| Remove["rm -f /etc/telegraf/FLUENTD_ENABLED\nrestart delphix-telegraf"]

    S --> Stat["print flag state\nprint systemctl is-active"]
```

---

## 5. Known Gaps and Open Questions

These must be answered before this feature is promoted to GA:

| # | Question | Owner | Impact |
|---|---|---|---|
| G1 | Does `_time` in seconds (vs Java's milliseconds) break Splunk mstats queries or Datadog ingest? | Seb | High — dashboard breakage |
| G2 | Does `systemVersion` as a full build string break customer dashboard filters? | Seb | Medium |
| G3 | Do any customer Splunk dashboards query the `data` sub-object (raw jiffy/bytes breakdown)? | Seb | Medium |
| G4 | Does `type: "g"/"c"` matter to any downstream plugin? | Seb | Low |
| G5 | Does the HEC nested structure (`fields: {...}`) work with existing customer `fluent-plugin-splunk-hec` configs without `data_type metric`? | Seb | High |
| G6 | Are `system.tcp.total.bytes` values from connstat semantically equivalent to what Java's `LocalTCPStatsCollector` sent? (cumulative per-connection vs delta per-endpoint) | Engineering | Medium |
| G7 | What is the validation plan for NFS/iSCSI metrics on an engine with active NFS/iSCSI traffic? | Engineering | High |

---

## 6. Stop-Gap Position and Urgency

### 6.1 Two Customer Segments, Different Urgency

| Segment | Java path state | Impact today | Stop-gap available? |
|---|---|---|---|
| **DE standalone** (no DCT) | Running ✅ | No impact | Yes — Java continues |
| **DE + DCT** | Disabled ❌ | **Already broken** — zero metrics reaching Splunk/Datadog | **No stop-gap** — needs this fix |

The "keep Java running in parallel" stop-gap only works for standalone engines. For DCT-managed engines, this PR **is** the stop-gap. Those customers are already getting zero data.

### 6.2 Two-Track Approach

```mermaid
graph TD
    subgraph Track1["Track 1 — DCT engines (urgent)"]
        A1["Answer open questions G1-G5\n(format compatibility)"] --> B1["Integration test on engine with active DCT"]
        B1 --> C1["Enable perf_fluentd in app-gate\nfor DCT-managed engines only"]
        C1 --> D1["Monitor customer Splunk/Datadog\nfor data continuity"]
    end

    subgraph Track2["Track 2 — Standalone engines (measured)"]
        A2["Full design sign-off"] --> B2["Customer beta test\n(volunteer Splunk customer)"]
        B2 --> C2["Enable for standalone engines"]
    end

    style Track1 fill:#ffdddd
    style Track2 fill:#ddffdd
```

### 6.3 Recommended Stop-Gap Actions (Current Release)

1. **Ship this code** — it is off by default and does not interfere with the Java path.
2. **DCT engines**: Prioritise answering G1 (time unit), G5 (HEC structure compatibility) — these are the only blockers for the DCT use case. Target: 1 sprint.
3. **Standalone engines**: Keep Java path active. Do NOT call `perf_fluentd enable` in app-gate for standalone engines until the full design is reviewed and tested.
4. **App-gate companion (PR #5043)**: Gated behind design review — do not merge until open questions are answered.

```mermaid
gantt
    title Recommended Timeline
    dateFormat YYYY-MM-DD

    section Immediate (current release)
    Ship code, fluentd off by default       :done,    2026-10-28, 1d
    Java continues for standalone engines   :done,    2026-10-28, 60d
    DCT engines: metrics broken (known gap) :crit,    2026-10-28, 14d

    section Sprint 1 (DCT fix — urgent)
    Answer G1 + G5 (time unit, HEC compat) :active,  2026-11-01, 7d
    Integration test: DCT + Splunk          :         2026-11-08, 7d
    Enable for DCT engines in app-gate      :         2026-11-15, 1d

    section Sprint 2 (GA — standalone)
    Full design review sign-off             :         2026-11-17, 7d
    Answer G2-G4, G6-G7                     :         2026-11-17, 7d
    Customer beta test (Splunk lab)         :         2026-11-24, 14d
    Enable for standalone engines           :         2026-12-08, 1d
```

---

## 7. Testing Plan (for GA)

| Test | What it verifies |
|---|---|
| `perf_fluentd enable` on a clean engine | Flag created, service restarts, fluentd stanza present in conf |
| `perf_fluentd disable` | Flag removed, stanza absent, InfluxDB output unaffected |
| Both InfluxDB + fluentd enabled | Both outputs in conf, storage_io inputs present, no discard |
| Neither enabled | `[[outputs.discard]]` in conf, Telegraf starts without error |
| Partial package (processor missing) | `logger` ERROR logged, service starts with raw names (documented fallback) |
| CPU metric value vs Java baseline | `system.cpu.util.pct` within ±1% of Java value at same point in time |
| Net/disk/tcp delta correctness | Download 100 MB, verify `system.net.total.bytes` ≈ 100 MB in that minute |
| NFS/iSCSI ops on active NFS mount | `system.nfs.ops.count` > 0 when NFS traffic active |
| Splunk end-to-end (lab) | Events appear in Splunk with correct `metric_name`, queryable via mstats |
| Datadog end-to-end (lab) | Events appear in Datadog metrics explorer |
| Service restart data gap | Restart Telegraf mid-minute; confirm at most one event missing |
| Concurrent enable/disable | Rapid enable/disable in loop; conf always valid, no half-written file |

---

## 8. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `_time` unit mismatch breaks Splunk mstats | Medium | High | Test in Splunk lab before GA; add explicit ms conversion if needed |
| `systemVersion` format breaks dashboard filters | Low | Medium | Strip to short form (e.g. `6.0.1.0`) at envsubst time |
| connstat instability causes `system.tcp.total.bytes` gaps | Medium | Low | Metric was absent in some Java releases too; acceptable |
| Starlark bucket logic has timing edge case at restart | Low | Low | At most one 60s gap; existing Java path also had restart gaps |
| InfluxDB receives `system.*` measurements (no namedrop) | High | Low | Extra series but no correctness impact; add namedrop in follow-up |
| NFS/iSCSI `iops(/s) * 10` breaks if estat interval changes | Low | Medium | Document coupling; add assertion in CI |

---

## 9. Appendix — File Inventory

```
performance-diagnostics/
├── telegraf/
│   ├── perf_fluentd                  ← NEW: enable|disable|status CLI
│   ├── telegraf.outputs.fluentd      ← NEW: HTTP output stanza
│   ├── telegraf.processors.fluentd   ← NEW: starlark transform
│   └── delphix-telegraf-service      ← MODIFIED: fluentd awareness
└── debian/
    └── rules                         ← MODIFIED: installs perf_fluentd
```

**Companion app-gate change (separate PR):**
```
dlpx-app-gate/
└── appliance/src/.../fluent.conf.stg  ← adds <source @type http port 9880>
                                          and data_type metric in <match>
```
