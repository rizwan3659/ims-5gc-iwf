# 1. Executive Summary

## Overview

The **IWF (Interworking Function)** is a carrier-grade signalling node that
translates between **IMS Diameter** interfaces (Cx/Dx, Sh, and dictionary
scaffolding for SWx/Zh) and **5G Core Service-Based Interfaces** (Nudm,
Nudr, Nausf, Namf via NRF discovery). It lets a legacy IMS core (I/S-CSCF,
application servers) interoperate with a 5G core (UDM/UDR/AUSF/AMF) without
either side being aware of the other's protocol.

It is a Rust Cargo workspace of 11 crates following **hexagonal
architecture**, deployed as a stateless, horizontally-scaled,
Kubernetes-native service.

## Purpose & business objective

Operators migrating from 4G/IMS to 5G run both cores during a multi-year
transition. The IWF protects the IMS investment by terminating its Diameter
signalling and serving it from 5G-core subscriber data — avoiding a forklift
upgrade of the IMS and a duplicate subscriber database.

## Main capabilities & use cases

- **Diameter stack**: zero-copy AVP codec (RFC 6733), peer state machine
  (§5.6) with RFC 3539 watchdog, CER/CEA/DWR/DWA/DPR/DPA.
- **Rule-driven translation**: declarative YAML/TOML DSL mapping Diameter
  commands → SBI calls; hot-reloadable; A/B staged rollout; plugin trait for
  custom answer builders.
- **SBA client**: pooled HTTP/2 (h2c) with circuit breaker and
  idempotency-aware retries.
- **NRF integration**: register / heartbeat / discover with a TTL endpoint
  cache and failure-driven re-discovery.
- **Security**: TLS 1.3 configs with hot cert reload, OAuth2 token cache,
  JWT validation, RBAC for the admin API.
- **Observability**: Prometheus metrics, JSON logging with runtime level
  switch, PII redaction.
- Verified use case: **Cx UAR → Nudm_SDM am-data → UAA** against Open5GS.

## Overall code-quality assessment

**Strong (B+/A‑).** The codebase is idiomatic, defensively written, and
unusually well-tested for its age: 129 unit/property/integration tests,
`#![deny(warnings)]` and `#![forbid(unsafe_code)]` in every crate, clean
`clippy -D clippy::all`, and a no-`unwrap`/`expect`/`panic` gate on production
paths. The hexagonal boundary is real (the domain crate has zero I/O deps).
It has been exercised live against a real 5G core, which surfaced and fixed
five genuine interop bugs (see Code Review Report §Defects).

The main gap is **breadth of integration, not depth of quality**: several
library-complete, well-tested modules (routing, session table, full peer FSM,
TLS wiring) exist but are not yet on the running node's active path, which
currently terminates Cx/Sh and translates to SBA rather than relaying or
originating Diameter.

## Key strengths

1. **Zero-copy, panic-free Diameter codec** with property-fuzzing — the most
   attacker-exposed parser is the most hardened part.
2. **Hexagonal discipline** — `iwf-core` defines ports; adapters convert at
   the boundary; the domain never imports a transport crate.
3. **Configuration-as-contract** — rules and config validate at load time and
   swap atomically (`ArcSwap`); a bad document can never go live.
4. **Operational maturity** — graceful drain, readiness gating, bounded
   shutdown, SLO-shaped metric buckets, FHS runtime kit with a SysV-style
   control script and a functional test suite.
5. **Honest, decision-recorded design** — five ADRs with rejected
   alternatives; a written "remaining scope" list.

## Major concerns

1. **Transport security is mesh-dependent** *(High)* — the Diameter listener
   and SBA client run cleartext; mTLS is delegated to a service mesh. The
   TLS 1.3 code exists but is not wired into the node. (OWASP A02.)
2. **Insecure-default auth path** *(Medium)* — without `IWF_OAUTH_CLIENT_ID`
   the SBA client sends a literal `"anonymous"` bearer; admin JWT secret
   defaults to `dev-secret` in the shipped env file.
3. **Token refresh is not single-flight** *(Medium)* — the doc-comment claims
   it is; under load the stale-window can trigger a refresh thundering herd.
4. **Unbounded Diameter connection acceptance** *(Medium)* — per-frame and
   in-flight limits exist, but there is no cap on concurrent peer connections
   (DoS surface). (OWASP A05.)
5. **Built-but-unintegrated modules** *(Low, clarity)* — `routing`,
   `session`, and the initiator half of the peer FSM are tested but unused by
   `iwf-node`; this should be documented or feature-gated to avoid confusion.

## Top recommendations (see Roadmap for full list)

| Priority | Recommendation |
|---|---|
| Immediate | Wire `tokio-rustls` into the Diameter listener and SBA/NRF clients; remove cleartext default. Replace `dev-secret`/`anonymous` defaults with fail-closed behaviour. |
| Short-term | Make OAuth token refresh genuinely single-flight; add a max-connections semaphore on the Diameter accept loop. |
| Medium-term | Integrate or feature-gate `routing`/`session`; wire NRF status-subscribe and cert-reload watcher; add coverage gate once toolchain allows. |
| Long-term | OTLP span export; outbound Diameter origination (RTR/PPR/PNR); object pools if profiling justifies; 100k-TPS acceptance on production hardware. |
