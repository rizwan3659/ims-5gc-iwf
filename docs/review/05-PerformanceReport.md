# 5. Performance Assessment

Targets (from the mandate): ≥100k TPS, internal p99 < 5 ms, end-to-end
p99 < 20 ms. Numbers below are **measured** on the test hardware unless noted.

## 5.1 Measured baselines

| Measurement | Value | Source |
|---|---|---|
| AVP/message decode | ≈ 353 ns/op (≈2.8M/s/core) | `cargo bench` (verified) |
| Message encode | ≈ 90 ns/op (≈11M/s/core) | `cargo bench` (verified) |
| Internal p99 (loopback mock, 20k TPS) | ≈ 1 ms (well < 5 ms) | loadgen + metrics (verified) |
| End-to-end p99 vs real Open5GS UDM | ≈ 8–15 ms | loadgen (verified) |
| Allocations per transaction | ≈ 2 (frame in, answer out) | code analysis |

The codec is ~3 orders of magnitude inside its per-message budget at 100k TPS
on modest cores; the bottleneck is I/O + NF latency, not the IWF's CPU.

## 5.2 Hotspots & allocation patterns

| Area | Assessment |
|---|---|
| Diameter decode | Zero-copy (`Bytes` slices), bounds-checked. Optimal. |
| Diameter encode | One sized `BytesMut` per answer. Good. |
| Translation | `TranslationContext { request: request.clone() }` clones the message (`Vec<Avp>`; each `Avp.data` is a cheap `Bytes` refcount bump, but the Vec itself allocates). One extra alloc/tx. (P-03) |
| SBA body | Rule body templates rendered via `serde_json` → `Bytes`. Allocates only when a rule has a body (GET paths don't). |
| Metrics | `with_label_values` does a per-call label lookup + format of `operation` string each SBA call (P-04). |

## 5.3 Synchronization / locking (see `docs/lld.md` for full inventory)

| Site | Type | Contention | Verdict |
|---|---|---|---|
| Pending tx (unused by node) | DashMap | n/a | fine when integrated |
| Discovery cache | DashMap | ~zero (per-NF key, read-mostly) | good |
| Breaker states | DashMap | low (per-endpoint) | good |
| Rules / TLS config | ArcSwap | none on read | excellent |
| OAuth token cache | tokio::Mutex | **elevated in stale window** | P-01 (D-02) |
| Route RR cursor | AtomicUsize (relaxed) | none | good |

## 5.4 Blocking / async hygiene

- No blocking calls on the async runtime (no `std::fs`/sync I/O in hot paths;
  config/rules read once at startup).
- Per-transaction work is a spawned task with a hard deadline
  (`transaction_timeout`), preventing slow NFs from pinning the pipe.
- Writer task **coalesces** queued answers before flush — good for syscall
  amortization at high TPS.

## 5.5 Findings & optimizations (with estimated impact)

| ID | Finding | Recommendation | Est. impact |
|---|---|---|---|
| P-01 | OAuth refresh awaited inline in stale window (D-02) | Single-flight + serve-stale-immediately | Removes refresh latency spikes (~token-RTT) from ~20% of requests during rollover; eliminates AS herd |
| P-02 | Per-transaction task spawn | Acceptable; Tokio spawn is cheap. Only revisit if profiling shows scheduler pressure at 100k TPS | Low |
| P-03 | Message clone into `TranslationContext` | Pass `&Message` + borrow vars; or `Arc<Message>` | ~1 alloc/tx saved; modest at 100k TPS |
| P-04 | `operation` label formatted per SBA call | Precompute per-rule operation label once | Saves a `format!` + map insert per call; small |
| P-05 | Session reaper O(n) scan at 4 Hz (when integrated) | Use a time-ordered structure (e.g. `BTreeMap<deadline,hbh>`) if pending sets grow large | Relevant only for the relay path |
| P-06 | NUMA pinning is documented, not enforced | On multi-socket nodes, pin pods via CPU Manager + Topology Manager single-numa-node | Tail-latency improvement on NUMA hosts |

## 5.6 Caching / batching / parallelism opportunities

- **Caching**: discovery (TTL) and OAuth tokens already cached. Could cache
  per-rule compiled templates (split static/dynamic segments) to avoid
  re-scanning on every call — minor.
- **Batching**: writer already coalesces answers; HTTP/2 multiplexes SBI.
- **Parallelism**: work-stealing Tokio runtime sized to cores (ADR-0001);
  horizontal scale is the primary throughput axis (stateless pods).

## 5.7 Outstanding validation

- The **100k TPS acceptance run** has only been demonstrated at lower rates on
  shared/loopback hardware. Recommend the runbook's multi-generator procedure
  on production-shaped NICs before sign-off (`docs/runbook.md` §Benchmarking).
