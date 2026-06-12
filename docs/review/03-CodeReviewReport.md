# 3. Code Review Report

Covers all 30 source files across 11 crates. Per-module review first, then a
consolidated **defect & risk register** (the actionable part), then
**maintainability scoring**.

---

## 3.1 Per-module review

### `iwf-core` (domain, zero I/O deps)

| File | Purpose | Notes |
|---|---|---|
| `identity.rs` | Validated newtypes `Impi/Impu/Supi/Suci/Gpsi` (TS 23.003), `IdentityContext`, IMPI→SUPI derivation | Macro-generated newtypes; `check_len` caps at 256 octets. Clean. |
| `auth.rs` | `AuthContext` (RAND/AUTN/XRES*/CK'/IK'), `AuthScheme` | `Debug` redacts key material (good); `validate()` enforces octet lengths. |
| `error.rs` | `CoreError` taxonomy + `ResultExt` | `#[non_exhaustive]`; adapters convert at the boundary. |
| `nf.rs` | `NfType` enum + str round-trip | Trivial, correct. |
| `ports.rs` | `SbaPort`, `EndpointResolver`, `TokenProvider`, `SbiRequest/Response`, `SbiMethod` | The hexagonal contract; `SbiMethod::idempotent()` drives retry safety. |

**Assessment:** exemplary. The domain is pure, well-typed, and the
`idempotent()` predicate centralises a safety-critical decision. No defects.

### `iwf-diameter`

| File | Purpose | Notes |
|---|---|---|
| `avp.rs` | Zero-copy AVP codec, typed accessors, builders | Bounds-checked before every slice; proptest-fuzzed. See D-09. |
| `message.rs` | Header codec, `find/find_all`, `MessageBuilder` | `answer_to` copies hbh/e2e per §6.2. Solid. |
| `dictionary.rs` | App ids, command/AVP/result codes | Spec-cited constants. |
| `base.rs` | CER/CEA/DWR/DWA/DPR/DPA build + `parse_capabilities` | Correct; P-bit cleared on base messages. |
| `peer.rs` | Pure FSM (RFC 6733 §5.6) + RFC 3539 watchdog + election | Pure function → exhaustively unit-tested. Initiator half unused by node (D-07). |
| `routing.rs` | Realm/app routing, RR/least-conn/weighted | Library-complete, **unused by `iwf-node`** (D-07). |
| `session.rs` | Pending-tx `DashMap`, Session-Id gen, failover/reaper | Library-complete, **unused by `iwf-node`** (D-07). |
| `transport.rs` | Length-delimited framing, DoS frame cap | Generic over `AsyncRead/Write` (TLS-ready) but node uses plain TCP (D-01). |
| `error.rs` | `DiameterError` | Thorough variants. |

**Assessment:** the strongest crate. Zero-copy + panic-free + fuzzed. Main
note is integration breadth (routing/session built but off the active path).

### `iwf-translation`

| File | Purpose | Notes |
|---|---|---|
| `rule.rs` | DSL schema, validation, A/B select, `RuleStore` (ArcSwap) | Load-time validation is a real strength; `ActionMap` TryFrom works around serde_yaml externally-tagged enums. |
| `engine.rs` | Action interpreter, `{var}`/`{{}}` substitution | Brace-escaping bug found & fixed (D-fixed-3). Clones request per tx (P-03). |
| `plugin.rs` | `TranslationPlugin` registry + builtin answer builders | MAA builder folds `Av5gAka` → SIP-Auth-Data-Item. |
| `mapping.rs` | AVP-name registry, TBCD codec, Av5gAka parse, IMPI↔SUPI | Spec-clause table in module docs. |

**Assessment:** the design centrepiece; configuration-as-contract done well.

### `iwf-sba`

| File | Purpose | Notes |
|---|---|---|
| `client.rs` | Pooled HTTP/2 client, endpoint walk, retry+breaker | In-transaction failover; 5xx counted against breaker. h2c default (D-01). |
| `breaker.rs` | Per-endpoint circuit breaker | Closed→Open→HalfOpen; single probe. Clean. |
| `retry.rs` | Idempotency-gated retry, full-jitter backoff | Correctly refuses to replay POST/PATCH. |
| `error.rs` | `SbaError` | Folded to `CoreError::NfUnavailable` at port. |

### `iwf-discovery`

| File | Purpose | Notes |
|---|---|---|
| `nrf.rs` | Register/heartbeat/discover; h2c + requester-type configurable | json-patch content-type fix (D-fixed-5). |
| `cache.rs` | TTL endpoint cache; `base_uri()` from apiPrefix/ipEndPoints/fqdn | ipEndPoints support added (D-fixed-4). |
| `heartbeat.rs` | Two-phase register→beat task, backoff, re-register on 404 | Exposes `is_registered` for readiness. |
| `profile.rs` | `NfProfile`/`NfService`/`IpEndPoint`/`SearchResult` | camelCase serde; `for_iwf` advertises capabilities. |

### `iwf-security`

| File | Purpose | Notes |
|---|---|---|
| `tls.rs` | TLS 1.3-only rustls server/client, hot reload | Correct & tested but **not wired into the node** (D-01). |
| `oauth.rs` | OAuth2 client-credentials token cache | Refresh **not single-flight** despite comment (D-02). Anonymous fallback (D-04). |
| `jwt.rs` | RS256/HS256 validation (sig/exp/aud/scope) | Coarse errors (good — no oracle). |
| `rbac.rs` | Role→permission, scope→role | Clean lattice. |

### `iwf-observability` / `iwf-config` / `iwf-admin`

| File | Purpose | Notes |
|---|---|---|
| `observability/metrics.rs` | All spec'd Prometheus families, SLO buckets | `operation` label contains a space — bit consumers (D-08). |
| `observability/logging.rs` | JSON subscriber, runtime level reload | `pii::render` redacts unless `pii-logging` feature. |
| `config/lib.rs` | Schema, validation, inotify watch | deny-unknown-fields; good. |
| `admin/lib.rs` | Axum router, RBAC middleware, health/ready | `validate_with_any_iwf_scope` is a slightly awkward shim (D-10). |

### `iwf-node` (composition root)

| File | Purpose | Notes |
|---|---|---|
| `main.rs` | Wiring, env config, drain sequence, bounded shutdown | `AnonymousTokens` insecure default (D-04). No max-connections cap (D-05). |
| `diameter_front.rs` | Listener, per-conn reader/writer tasks, ingress shed, FSM | Shed path uses `try_send` (may drop busy answer, D-06). Cert reload not wired (D-01). |

### `iwf-benchmark`

| File | Purpose | Notes |
|---|---|---|
| `lib.rs` | Sample UAR fixture | — |
| `benches/codec.rs` | Criterion codec benches | decode≈353ns, encode≈90ns (measured). |
| `bin/loadgen.rs` | Diameter load generator (`--count` added) | Good test tool. |
| `bin/mock5gc.rs` | In-process NRF+UDM mock | Enables hermetic tests. |

---

## 3.2 Defect & Risk Register

Severity: **Critical** (exploitable/data-loss) · **High** · **Medium** ·
**Low**. Items prefixed `D-fixed-*` were found and fixed during the live
Open5GS bring-up and are recorded for traceability.

### D-01 — Cleartext transport on the active path · **High** · OWASP A02
- **Impact:** Diameter (3868) and SBI (h2c) traffic — IMSIs, auth vectors —
  travel unencrypted unless a service mesh provides mTLS. Signalling
  interception / MITM if the mesh is absent or misconfigured.
- **Root cause:** `transport.rs` is generic over the stream and `iwf-security::tls`
  is complete, but `diameter_front.rs` accepts `TcpStream` directly and
  `iwf-sba`/`iwf-discovery` build plain `HttpConnector`s. TLS is never wired.
- **Fix:** wrap the accept path in `tokio_rustls::TlsAcceptor` (config from
  `ReloadableServerTls`) and use a rustls HTTPS connector for the clients;
  gate cleartext behind an explicit `--insecure` flag.
- **Patch sketch:**
  ```rust
  // diameter_front.rs accept loop
  let tls = acceptor.accept(stream).await?;      // tokio_rustls::TlsAcceptor
  front.handle_connection(tls).await;             // handle_connection is already generic-ready
  ```

### D-02 — OAuth token refresh is not single-flight · **Medium**
- **Impact:** during the 20% stale window, every concurrent request triggers
  its own `refresh()` → token-endpoint thundering herd; also adds refresh
  latency to those requests (it awaits the refresh before returning the old
  token).
- **Root cause:** `oauth.rs::bearer_token` drops the lock then calls
  `self.refresh().await` per caller; the doc-comment claims single-flight.
- **Fix:** guard refresh with a per-NF `tokio::sync::Mutex<()>` or an
  in-flight `Notify`, or spawn a single background refresher; return the
  cached token immediately without awaiting.
- **Patch sketch:**
  ```rust
  // serve stale immediately; refresh in the background once
  let token = cached.token.clone();
  if self.refresh_lock.try_lock().is_ok() { let me = self.clone(); tokio::spawn(async move { let _ = me.refresh(target).await; }); }
  return Ok(token);
  ```

### D-03 — Unauthenticated Diameter ingress relies on network policy · **Medium** · OWASP A07
- **Impact:** any host that can reach 3868 and send a valid CER becomes a
  peer. Diameter has no per-message auth here; only realm/application
  filtering on CER.
- **Root cause:** by-design for Diameter, but combined with D-01 and no
  per-peer allow-list it widens the surface.
- **Fix:** enforce mTLS (D-01) as peer authentication; add a configurable
  Origin-Host/realm allow-list checked in `parse_capabilities`.

### D-04 — Insecure defaults · **Medium** · OWASP A05
- **Impact:** `AnonymousTokens` sends `Bearer anonymous` when
  `IWF_OAUTH_CLIENT_ID` is unset; `deploy/cdot/cdot_iwf.env` ships
  `IWF_ADMIN_JWT_SECRET=dev-secret`. A deployment that forgets to override
  runs with no real SBI auth and a guessable admin secret.
- **Fix:** fail-closed — refuse to start without explicit OAuth config unless
  `--lab` is passed; generate a random admin secret at install if unset and
  log a warning; mark the env value `CHANGE_ME` and refuse `dev-secret` in a
  `prod` profile.

### D-05 — No cap on concurrent Diameter connections · **Medium** · OWASP A05 (DoS)
- **Impact:** the accept loop spawns a task per connection unboundedly; a
  flood of half-open CERs can exhaust memory/fds even though per-frame and
  in-flight limits exist.
- **Root cause:** `diameter_front.rs::spawn` accept loop has no semaphore.
- **Fix:** bound with `tokio::sync::Semaphore` sized from config
  (`max_connections`); reject/close beyond it.

### D-06 — Overload-shed answer may be silently dropped · **Low**
- **Impact:** under ingress shed, `error_answer(..3004..)` is sent with
  `try_send`; if the writer queue is full the busy answer is dropped and the
  peer must time out instead of getting a fast 3004.
- **Fix:** acceptable under extreme overload, but prefer a small dedicated
  priority path or `send().await` with a short timeout for control answers.

### D-07 — Built-but-unintegrated modules · **Low (clarity/maintenance)**
- **Impact:** `routing.rs`, `session.rs`, and the initiator half of `peer.rs`
  are fully tested but unreferenced by `iwf-node` (which terminates Cx/Sh and
  translates to SBA — it does not relay or originate Diameter). New engineers
  may assume they are on the hot path.
- **Fix:** document in each module header that it serves the (future) relay /
  origination path, or place behind a `relay` cargo feature until wired.

### D-08 — Metric label contains a space (consumer foot-gun) · **Low**
- **Impact:** `iwf_sba_requests_total{...,operation="Get /nudm-sdm/..."}` has
  a space in the label *value*; naive `awk '{print $2}'` reads the wrong
  field (this exact bug bit the first version of `tests.sh`).
- **Root cause:** `main.rs::MeteredSba` formats `operation` as `"{:?} {}"`.
- **Fix:** either split into `method` + `operation` labels, or join without a
  space (`"GET:/nudm-sdm/..."`). Low risk (legal Prometheus), but tidy.

### D-09 — Grouped-AVP depth budget is advisory, not enforced across calls · **Low**
- **Impact:** `Avp::as_grouped_depth` checks `depth==0` but each top-level
  `as_grouped()` call resets the budget to `MAX_GROUP_DEPTH`; a consumer
  manually walking nested groups never decrements it. No actual stack-overflow
  risk because decoding is lazy and iterative (bounded by buffer length), so
  this is a latent inconsistency, not an exploitable bomb.
- **Fix:** have `as_grouped()` recurse and thread the decremented budget, or
  drop the unused `depth` parameter to avoid implying a guarantee it doesn't
  give.

### D-10 — Admin scope check shim is awkward · **Low**
- **Impact:** `admin/lib.rs::validate_with_any_iwf_scope` loops over the three
  scope strings calling `validate(token, scope)`; correct but does up to 3
  JWT verifications. Minor CPU; clarity.
- **Fix:** validate signature/exp/aud once, then resolve role from the decoded
  `scope` claim directly.

### Fixed during live bring-up (traceability)
- **D-fixed-1**: `NrfClient` defaulted to HTTP/1.1 → unreachable h2c NRF;
  added `with_http2`/`configured`. *(verified)*
- **D-fixed-2**: discovery `requester-nf-type` hardcoded → Open5GS returned
  empty UDM list; made env-configurable (`IWF_NRF_REQUESTER_NF_TYPE`).
- **D-fixed-3**: `{var}` substitution collided with literal JSON braces in the
  `plmn-id` value → request failed pre-UDM; added `{{`/`}}` escaping.
- **D-fixed-4**: UDM advertised address in `ipEndPoints`, not `apiPrefix` →
  discovery yielded no endpoint; added `IpEndPoint` + `NfService::base_uri()`.
- **D-fixed-5**: heartbeat PATCH used `application/json` → Open5GS 400; switched
  to `application/json-patch+json`.
- **D-fixed-6**: unbounded `Runtime::drop` could hang shutdown; added
  `runtime.shutdown_timeout(5s)`.

---

## 3.3 Maintainability assessment (1–10)

| Category | Score | Justification |
|---|---:|---|
| Code readability | 9 | Idiomatic Rust, dense rustdoc, spec citations inline. |
| Separation of concerns | 9 | Real hexagonal boundary; domain has zero I/O deps. |
| Modularity | 9 | 11 focused crates; clear ownership. |
| Reusability | 8 | Ports + plugin trait; routing/session reusable (if integrated). |
| Naming conventions | 9 | Consistent, spec-aligned (AVP/NF names). |
| Consistency | 8 | Uniform error style; minor inconsistency in TLS wiring vs. intent. |
| Technical debt | 7 | Built-but-unintegrated modules (D-07); cleartext default (D-01). |
| Documentation quality | 9 | ADRs, HLD/LLD, runbook, OpenAPI, deploy/test guides. |
| Test quality | 8 | 129 tests incl. property + e2e; coverage gate not yet enforced. |
| Ease of onboarding | 8 | Strong docs + control script; the unintegrated modules can mislead. |
| **Overall** | **8.4** | Production-grade quality; gaps are integration breadth and transport security, not craftsmanship. |
