# IWF — IMS ↔ 5G Core Interworking Function

Carrier-grade signaling node translating between IMS Diameter interfaces
(Cx, Dx, Sh, SWx, Zh) and 5G Core service-based interfaces (UDM, UDR, AUSF,
AMF, PCF via NRF discovery). Rust workspace, Kubernetes-native, zero-downtime
upgrades.

## Layout

| Crate | Role |
|---|---|
| `iwf-core` | Domain model + ports (hexagonal core, zero I/O deps) |
| `iwf-diameter` | Standalone Diameter stack: zero-copy codec, RFC 6733 §5.6 peer FSM, realm/app routing (RR / least-conn / weighted), DashMap session table |
| `iwf-sba` | HTTP/2 SBA client: pooling, circuit breaker, idempotency-gated retries |
| `iwf-translation` | YAML/TOML rule DSL, hot-swap rule store, plugin registry, AVP↔JSON mappings with spec clauses |
| `iwf-discovery` | NRF register/heartbeat/discover, TTL endpoint cache, failover |
| `iwf-security` | TLS 1.3-only + mTLS, cert hot-reload, OAuth2 token cache, JWT, RBAC |
| `iwf-observability` | Prometheus metrics, JSON logging w/ runtime level switch, PII redaction |
| `iwf-admin` | Management REST API (Axum) + OpenAPI spec |
| `iwf-config` | Validated config schema + inotify hot reload |
| `iwf-benchmark` | Criterion codec benches + Diameter TPS load generator |
| `iwf-node` | Composition-root binary (listener, drain, wiring) |

Docs: `docs/adr/` (decisions), `docs/hld.md`, `docs/lld.md`,
`docs/runbook.md`, `docs/production-readiness.md`,
`docs/deploy-open5gs.md` (manual build/deploy/test against an Open5GS core).
Deploy: `deploy/k8s/`, `deploy/helm/iwf/`, `deploy/istio/`, `Dockerfile`,
`.github/workflows/ci.yml`.

## Build & test

```sh
cargo build --release --locked     # rustc 1.75 (deps pinned; see ADR-0005)
cargo test --workspace             # unit + property + e2e (in-process mocks)
cargo bench -p iwf-benchmark       # codec micro-benchmarks
```

Run locally (lab mode, no OAuth):

```sh
IWF_CONFIG=config/config.yaml IWF_SBA_HTTP1=1 \
IWF_E2E_JWT_SECRET=dev cargo run -p iwf-node
```

Load test: `cargo run --release -p iwf-benchmark --bin loadgen -- host:3868
--tps 25000 --connections 16 --seconds 300` (acceptance procedure:
`docs/runbook.md` §Benchmarking).

## Remaining scope (explicit, per the delivery mandate)

1. **Direct rustls mTLS on the SBA client and Diameter listener** — TLS 1.3
   configs and hot-reload exist in `iwf-security`; the SBA connector and the
   Diameter accept path currently run cleartext with mesh-provided mTLS
   (Istio overlay included). Wiring `tokio-rustls` into
   `transport::read_frame`'s generic stream and a rustls hyper connector is
   the next increment.
2. **Outbound Diameter request origination** (network-initiated RTR/PPR/PNR
   toward IMS): the session table, routing and FSM support it; the trigger
   path (5GC notification → Diameter request) is not wired.
3. **NRF status-notification subscriptions** — cache invalidation is
   TTL/poll + failure-driven today (`NFStatusSubscribe` callback endpoint
   not implemented).
4. **OTLP span export** — span structure and correlation ids are in place
   via `tracing`; the OpenTelemetry exporter sits behind the disabled
   `otlp` feature pending a toolchain bump (its current crates need newer
   rustc than the pinned 1.75).
5. **Coverage gate** — tarpaulin job included in CI but informational on
   this toolchain (see `docs/production-readiness.md` OPEN items).
6. **Object pools for message structs** — current hot path is 2 allocations
   per transaction (frame in, answer out), measured ≪ the latency budget;
   pooling is prepared for but not justified by profiling yet.
7. **Sh SNR/PNR subscription state, Dx/SWx/Zh full command sets** — routing
   and dictionary entries exist; rules ship for the mandated table only.
8. **PCF flows** — NF type, discovery and client support exist; no default
   rules target PCF yet.
