# Production Readiness Checklist — mapped to operational targets

## ≥100k TPS sustained
- [x] Zero-copy codec, 2 allocations/transaction on the Diameter side
      (micro-benchmarked in CI: `cargo bench -p iwf-benchmark`).
- [x] HTTP/2 multiplexed pooled SBA client; no per-request connections.
- [x] Stateless horizontal scaling + HPA manifest.
- [x] Load generator (`loadgen`) for acceptance runs.
- [ ] OPEN: 100k acceptance run on production-shaped hardware (procedure in
      runbook §Benchmarking) — cannot be demonstrated in this dev container.

## p99 internal <5 ms / end-to-end <20 ms
- [x] SLO-shaped histogram buckets; internal vs SBA latency separable.
- [x] Ingress shedding (3004) protects latency under overload.
- [x] Bounded writer queues; no unbounded buffering anywhere on the path.
- [x] Per-transaction deadline (5 s hard stop, configurable).

## Five-nines availability
- [x] Peer watchdog + failover; pending-transaction failover on peer loss.
- [x] Circuit breaker + in-transaction endpoint failover (<500 ms).
- [x] NRF heartbeat re-registration; discovery cache rides NRF outages.
- [x] Validated hot-reload (rules/config/certs) — bad input cannot
      dethrone good state.
- [x] PDB, anti-affinity, topology spread, multi-zone manifests.
- [x] Graceful drain on SIGTERM (zero-downtime rolling upgrades).

## Tens of millions of subscribers
- [x] No per-subscriber state in the IWF (ADR-0004).
- [x] Metric label cardinality bounded (ids generalized to `{id}`).

## Security
- [x] TLS 1.3 only; mTLS server config; no runtime downgrade knob.
- [x] OAuth2 client-credentials cache (80% TTL refresh).
- [x] JWT sig/exp/aud/scope validation; RBAC (3 roles) on admin API.
- [x] No secrets in config files; env/Secret injection only.
- [x] PII redacted from logs unless `pii-logging` build feature.
- [x] NetworkPolicy restricting ingress to 3868/8080/9090.
- [ ] OPEN: direct rustls mTLS on SBA client (currently mesh-provided;
      see README Remaining scope).

## Observability
- [x] All spec'd metric families; peer-state gauge; correlation ids
      end-to-end (`x-correlation-id` header outbound).
- [x] JSON logs; hot-switchable level via admin API.
- [ ] OPEN: OTLP exporter wiring behind `otlp` feature (span structure in
      place via tracing instrumentation).

## Quality gates
- [x] `#![deny(warnings)]`, `#![forbid(unsafe_code)]` everywhere;
      clippy `-D warnings` in CI; rustfmt check.
- [x] No `unwrap()/expect()/panic!()` in non-test code paths
      (`expect` only in tests; grep-gated in CI).
- [x] Unit + property (proptest fuzz of the codec) + integration
      (in-process mock NRF/UDM/UDR, real binary, real TCP) tests.
- [ ] OPEN: coverage gate — tarpaulin needs a newer toolchain than this
      build container (CI job included but marked continue-on-error until
      the toolchain moves).
