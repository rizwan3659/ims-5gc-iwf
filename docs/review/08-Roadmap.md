# 8. Improvement Roadmap (prioritized)

Each item references the defect/security/perf ID it resolves. Effort is a
rough engineer-week estimate.

## Immediate (Critical / blockers for an untrusted network)

| Item | Resolves | Effort |
|---|---|---|
| Wire `tokio-rustls` into the Diameter listener + SBA/NRF clients; mTLS required; cleartext only behind `--insecure` | D-01, S-1, S-3 | 1.5w |
| Fail-closed auth defaults: refuse `dev-secret`/missing OAuth in prod profile; random-generate admin secret at install | D-04, S-2 | 0.5w |
| Add `cargo audit` + `cargo deny` (advisories + license gate) to CI | S-6 | 0.3w |
| Bound concurrent Diameter connections (Semaphore from config) | D-05, S-4 | 0.3w |

## Short-term (next iteration)

| Item | Resolves | Effort |
|---|---|---|
| Make OAuth token refresh single-flight + serve-stale-immediately | D-02, P-01 | 0.5w |
| Wire the cert-reload inotify watcher into `iwf-node` (TLS material) | D-01 follow-on | 0.3w |
| Validate path-segment `{var}`s against identity formats (or percent-encode) | S-path-traversal | 0.3w |
| Split metric `operation` into `method`+`operation` labels (no spaces) | D-08 | 0.2w |
| Add h2c integration test + MAR/PUR/breaker/NRF-down integration tests | T-INT-03..07 | 1w |
| Document or `relay`-feature-gate `routing`/`session`/initiator-FSM | D-07 | 0.3w |

## Medium-term

| Item | Resolves | Effort |
|---|---|---|
| Move fleet toolchain to current rustc; relax MSRV down-pins | S-6 | 1w |
| Enforce coverage gate (`cargo-tarpaulin` ≥ 90%) once toolchain allows | test gap | 0.3w |
| NRF status-subscribe (push invalidation) instead of TTL/poll only | reliability | 1w |
| OTLP span export behind `otlp` feature | observability | 0.5w |
| `serde_yaml` migration / standardise on TOML | dep risk | 0.5w |
| Object pools / `Arc<Message>` to shave the per-tx clone | P-03 | 0.5w |
| 100k-TPS acceptance on production-shaped hardware | perf validation | 0.5w |

## Long-term

| Item | Resolves | Effort |
|---|---|---|
| Outbound Diameter origination (RTR/PPR/PNR): wire `session`+`routing`+initiator FSM | feature | 3w |
| Sh subscription state (SNR/PNR) externalised to a KV/UDR | feature | 3w |
| PCF flows + Dx/SWx/Zh full command sets | feature | 2w+ |
| Direct `aws-lc-rs` rustls backend (FIPS posture) | security | 1w |
| SBOM per release (`cargo cyclonedx`) | supply chain | 0.3w |

## Definition of done for "production on an untrusted network"

1. mTLS on Diameter + SBI (Immediate).
2. No insecure defaults; secrets fail-closed (Immediate).
3. `cargo audit` clean in CI (Immediate).
4. Connection cap + verified shedding (Immediate/Short).
5. 100k-TPS acceptance signed off (Medium).
6. Coverage gate enforced (Medium).
