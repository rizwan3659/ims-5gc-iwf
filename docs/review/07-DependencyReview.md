# 7. Dependency Review

All dependencies are pinned exactly (`=x.y.z`) in `[workspace.dependencies]`
for rustc-1.75 reproducibility (ADR-0005). Licenses are all **permissive**
(MIT / Apache-2.0 / ISC) — no copyleft; safe for commercial distribution.

## 7.1 Direct dependencies

| Crate | Ver | License | Purpose | Action |
|---|---|---|---|---|
| tokio | 1.35.1 | MIT | Async runtime, net, sync, signals | Keep; upgrade when toolchain moves |
| bytes | 1.5.0 | MIT | Zero-copy buffers (codec core) | Keep |
| hyper | 1.1.0 | MIT | HTTP/2 client+server | Keep; track 1.x patches |
| hyper-util | 0.1.2 | MIT | Pooled legacy client, Tokio glue | Keep; 0.1.x is pre-1.0, watch API churn |
| http / http-body-util | 1.0.0 / 0.1.0 | MIT | HTTP types/bodies | Keep |
| axum | 0.7.4 | MIT | Admin API + test mocks | Keep |
| tower | 0.4.13 | MIT | Service middleware | Keep |
| rustls | 0.22.2 | Apache-2.0/ISC/MIT | TLS 1.3 (via `ring`) | Keep; **monitor RUSTSEC for ring/rustls** |
| tokio-rustls | 0.25.0 | MIT/Apache-2.0 | TLS stream glue | Keep (wire it — D-01) |
| rustls-pemfile | 2.0.0 | Apache-2.0/ISC/MIT | PEM parsing | Keep |
| jsonwebtoken | 9.2.0 | MIT | Admin JWT validate | Keep |
| serde | 1.0.195 | MIT/Apache-2.0 | (De)serialization | Keep |
| serde_json | 1.0.111 | MIT/Apache-2.0 | JSON bodies | Keep |
| serde_yaml | 0.9.30 | MIT/Apache-2.0 | Rule/config YAML | **Note: serde_yaml is now unmaintained upstream** — plan migration (see 7.3) |
| toml | 0.8.8 | MIT/Apache-2.0 | Config/rule TOML | Keep |
| dashmap | 5.5.3 | MIT | Sharded concurrent maps | Keep |
| arc-swap | 1.6.0 | MIT/Apache-2.0 | Lock-free config/rule swap | Keep |
| parking_lot | 0.12.1 | MIT/Apache-2.0 | (transitive use) | Keep |
| notify | 6.1.1 | CC0/Artistic-2.0 | Config inotify watch | Keep |
| tracing | 0.1.40 | MIT | Structured logging/spans | Keep |
| tracing-subscriber | 0.3.18 | MIT | JSON subscriber + reload | Keep |
| prometheus | 0.13.3 | Apache-2.0 | Metrics registry/exposition | Keep |
| rand | 0.8.5 | MIT/Apache-2.0 | Jitter, weighted LB, test data | Keep |
| futures | 0.3.30 | MIT/Apache-2.0 | Async combinators | Keep |
| async-trait | 0.1.77 | MIT/Apache-2.0 | Async trait objects (ports) | Keep |
| uuid | 1.7.0 | MIT/Apache-2.0 | NF instance / correlation ids | Keep |
| base64 | 0.21.7 | MIT/Apache-2.0 | (security helpers) | Keep |
| thiserror | 1.0.56 | MIT/Apache-2.0 | Error derives | Keep |
| criterion | 0.5.1 | MIT/Apache-2.0 | Benchmarks (dev) | Keep (dev) |
| proptest | 1.4.0 | MIT/Apache-2.0 | Property tests (dev) | Keep (dev) |

## 7.2 Notable transitive pins (for MSRV)

`indexmap 2.2.6`, `time 0.3.36`, `time-macros 0.2.18`, `clap 4.4.18`,
`rayon 1.8.1`, `half 2.2.1`, `crossbeam-* (0.8.x)` — pinned **down** because
newer releases require rustc ≥ 1.80/1.81/1.82. `ring` (via rustls) is the most
security-sensitive transitive.

**Supply-chain risk (Medium, OWASP A06):** pinning to older releases means
later security patches in those crates are *not* picked up automatically.
This is a deliberate MSRV trade-off, but it must be actively managed.

## 7.3 Recommendations

| Action | Priority | Rationale |
|---|---|---|
| Add `cargo audit` + `cargo deny` to CI | Immediate | Catch RUSTSEC advisories (esp. `ring`/`rustls`/`time`) and enforce the permissive-license policy automatically |
| Move fleet toolchain to current stable rustc | Short | Lets the MSRV down-pins (time/indexmap/clap/rayon/half) be relaxed to current, patched versions |
| Plan `serde_yaml` migration | Medium | Upstream is archived/unmaintained; candidates: `serde_yml` fork or standardise on TOML for rules/config |
| Pin/verify `ring` version and watch advisories | Short | Most security-relevant transitive; consider `rustls` + `aws-lc-rs` backend when toolchain allows |
| Generate an SBOM (`cargo cyclonedx`) per release | Medium | Supply-chain traceability for the operator |

No GPL/AGPL/LGPL or otherwise restrictive licenses are present. No dependency
is recommended for **removal** — all are load-bearing.
