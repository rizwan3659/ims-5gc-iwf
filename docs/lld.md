# IWF Low-Level Design

Authoritative API detail lives in rustdoc (`cargo doc --workspace`).
This file records the structure and the algorithms that matter.

## iwf-core (domain, no I/O)
- `identity`: validated newtypes `Impi/Impu/Supi/Suci/Gpsi` (TS 23.003
  format rules), `IdentityContext` + IMPI→SUPI derivation (§13.3).
- `auth`: `AuthContext` (RAND/AUTN/XRES*/CK'/IK'); `Debug` redacts key
  material; `sip_authenticate()` = RAND‖AUTN (TS 29.229 §6.3.10).
- `ports`: `SbaPort` (async request/response), `EndpointResolver`,
  `TokenProvider` — the only I/O surfaces the domain knows.
- `error`: `CoreError` taxonomy; adapters map into it at the boundary.

## iwf-diameter
- `avp`: zero-copy codec. `decode_at` validates code/flags/len/vendor
  against the enclosing buffer before slicing; padding arithmetic checked;
  grouped decode budgeted by `MAX_GROUP_DEPTH = 8`.
- `message`: header codec, `find/find_all`, `MessageBuilder`
  (`answer_to` copies hbh/e2e per RFC 6733 §6.2).
- `peer`: pure FSM `(state, event) → (state, actions)` per RFC 6733 §5.6
  incl. election (§5.6.4) and RFC 3539 watchdog (fail on 2nd missed DWA).
  Pure function ⇒ exhaustively unit-tested without sockets.
- `routing`: priority tiers, then strategy (RR via atomic cursor,
  least-connections via per-peer atomic in-flight, weighted via ticket
  draw). Table is an immutable snapshot for `ArcSwap`.
- `session`: `DashMap<hbh, PendingTx{oneshot, deadline, peer}>`;
  `fail_peer` (failover) and `reap_expired` (4 Hz) both O(scan).
- `transport`: `read_frame` validates the 4-byte prologue before the single
  frame allocation; max-frame DoS guard; generic over AsyncRead/Write so
  TLS streams plug in.

## iwf-translation
- `rule`: serde schema (single-key action maps via `ActionMap` TryFrom),
  load-time validation, A/B select via Knuth-hash bucket of e2e id,
  `RuleStore` = `ArcSwap<RuleSet>`.
- `engine`: sequential action interpreter; `{var}` substitution fails on
  unbound vars; errors map to protocol answers in the front-end.
- `plugin`: `TranslationPlugin` registry; built-ins for UAA/MAA/UDA success
  and 5001/5012 errors; MAA builder folds `Av5gAka` → SIP-Auth-Data-Item.
- `mapping`: AVP-name registry (load-time validation target), TBCD codec,
  Av5gAka parsing, IMPI↔SUPI; clause-by-clause table in the module docs.

## iwf-sba
- `client`: hyper-util pooled client (HTTP/2 prior knowledge in prod);
  endpoint walk per attempt = in-transaction failover; 5xx returned to
  rules but counted against breaker; idempotency gate (`SbiMethod`) decides
  retry; full-jitter exponential backoff.
- `breaker`: Closed→Open(threshold)→HalfOpen(single probe)→Closed.
- `error`: `SbaError` folded to `CoreError::NfUnavailable` at the port.

## iwf-discovery
- `nrf`: register (PUT), heartbeat (PATCH, 404 ⇒ re-register), deregister,
  discover (`SearchResult`).
- `cache`: `DashMap<NfType, {endpoints, healthy, expires}>`;
  `report_failure` marks unhealthy + expires entry (next resolve re-queries).
- `heartbeat`: two-phase task (register w/ backoff → beat at granted
  interval); exposes `is_registered` for readiness.

## iwf-security
- `tls`: TLS 1.3-only rustls server/client builders; mTLS verifier from CA
  bundle; `ReloadableServerTls` ArcSwap reload (bad rotation keeps old).
- `oauth`: `TokenCache` per NF type; stale at 80% TTL, hard stop at TTL;
  refresh failures serve cached until hard expiry.
- `jwt`: RS256 (prod) / HS256 (lab); aud+exp+scope enforced; coarse errors.
- `rbac`: operator ⊃ provisioning ⊃ read-only; scope → role → permission.

## iwf-observability / iwf-config / iwf-admin / iwf-node
- Metrics families exactly as spec'd; SLO-shaped histogram buckets.
- JSON tracing with `reload`-able level; PII redaction unless
  `--features pii-logging`.
- Config: deny-unknown-fields schema, semantic validation, inotify watch →
  `watch` channel of `Arc<Config>` snapshots.
- Admin: RBAC-gated axum router; rules PUT validates-then-swaps.
- Node: composition root; Diameter front-end (reader task + bounded writer
  queue per connection; ingress shed; per-transaction tokio task with
  deadline), MeteredSba decorator, drain sequence
  (ready=false → drain ≤ budget → DPR → NRF deregister).

## Locking inventory (expected contention)
| Site | Type | Contention |
|---|---|---|
| pending transactions | DashMap (sharded) | low — uniform hbh keys |
| discovery cache | DashMap | ~zero — per-NF-type keys, read-mostly |
| breaker states | DashMap | low — per-endpoint |
| rules / TLS config | ArcSwap | none on read |
| token cache | tokio::Mutex | low — hit path takes it briefly; refresh single-flight |
| route table cursor | AtomicUsize | none (relaxed) |
