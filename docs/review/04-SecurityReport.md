# 4. Security Assessment

Findings are mapped to **OWASP Top 10 (2021)** where applicable. Severities:
Critical / High / Medium / Low. Cross-references to the defect register
(`03-CodeReviewReport.md`) are noted.

## 4.1 Summary table

| ID | Finding | Severity | OWASP | Status |
|---|---|---|---|---|
| S-1 | Cleartext Diameter + SBI transport on active path | High | A02 Cryptographic Failures | Open (D-01) |
| S-2 | Insecure defaults (`anonymous` token, `dev-secret` JWT) | Medium | A05 Misconfiguration | Open (D-04) |
| S-3 | Diameter ingress unauthenticated beyond network policy | Medium | A07 Auth Failures | By design + D-03 |
| S-4 | No concurrent-connection cap (DoS) | Medium | A05 / DoS | Open (D-05) |
| S-5 | OAuth token refresh not single-flight (amplification) | Low | A05 | Open (D-02) |
| S-6 | Supply chain: dependencies pinned to old versions for MSRV | Medium | A06 Vulnerable Components | See Dependency Review |
| S-7 | PII (IMSI/SUPI) in debug-level paths/logs | Low | A09 Logging Failures | Mitigated (pii feature) |
| S-8 | Admin API exposure if bound to 0.0.0.0 without policy | Medium | A01 Broken Access Control | Config-dependent |

## 4.2 Positive controls (what's done right)

- **`#![forbid(unsafe_code)]`** in every crate — no memory-safety surface in
  the parser or anywhere else.
- **Panic-free production paths** — `clippy::unwrap_used/expect_used/panic`
  denied; malformed Diameter input returns `Err`, never aborts the process
  (DoS-resistant parsing; property-fuzzed in `proptest_roundtrip.rs`).
- **Bounded frame size** (`DEFAULT_MAX_FRAME` 1 MiB) checked *before*
  allocation — decompression/amplification guard.
- **Grouped-AVP recursion is lazy + iterative** — no stack-overflow bomb.
- **Secrets never in config** — TLS via Secret mounts, OAuth/admin via env
  injection; `AuthContext::Debug` redacts key material.
- **JWT validation is strict and coarse** — signature, `exp`, `aud`, `scope`
  all enforced; errors are opaque (no oracle).
- **RBAC** — three roles, least-privilege lattice, default-deny on unknown
  scope.
- **TLS 1.3-only** policy in `iwf-security::tls` (no downgrade knob).

## 4.3 Detailed findings

### S-1 — Cleartext transport (High, OWASP A02)
- **Evidence:** `diameter_front.rs` calls `listener.accept()` and uses the raw
  `TcpStream`; `iwf-sba::client` and `iwf-discovery::nrf` build
  `HttpConnector::new()` (no TLS). `iwf-security::tls` is implemented but
  unreferenced by `iwf-node`.
- **Exploit scenario:** an attacker on the signalling network (or a
  compromised sidecar/host) passively captures IMSIs, IMPIs, and 5G-AKA
  authentication vectors, or actively MITMs UAR/MAA to spoof registration.
- **Mitigation:** wire `tokio-rustls` (server + client) using the existing
  `ReloadableServerTls`; require mTLS for Diameter peers and SBI; keep
  cleartext only behind an explicit `--insecure`/lab flag. Until then,
  **mTLS via the service mesh is mandatory, not optional** — document and
  enforce the Istio overlay (`deploy/istio/`).

### S-2 — Insecure defaults (Medium, OWASP A05)
- **Evidence:** `main.rs::AnonymousTokens` → `Bearer anonymous`;
  `deploy/cdot/cdot_iwf.env` → `IWF_ADMIN_JWT_SECRET=dev-secret`.
- **Exploit scenario:** a production deploy that forgets overrides accepts
  admin calls signed with the known `dev-secret` (full operator control:
  rule replacement, log-level), and authenticates to NFs with no real token.
- **Mitigation:** fail-closed without explicit config; random-generate the
  admin secret at install; reject `dev-secret` in a production profile.

### S-3 — Unauthenticated Diameter ingress (Medium, OWASP A07)
- **Evidence:** peers are accepted on CER with only realm/application checks;
  no per-peer credential.
- **Mitigation:** mTLS as peer auth (S-1); add Origin-Host/realm allow-list.

### S-4 — Connection-flood DoS (Medium)
- **Evidence:** unbounded task-per-connection accept loop (D-05).
- **Mitigation:** `Semaphore`-bounded accept; per-IP connection limits at the
  LB/NetworkPolicy.

### S-5 — Token-refresh amplification (Low)
- See D-02. Bounded blast radius (own AS), but make refresh single-flight.

### S-6 — Supply-chain / pinned-old dependencies (Medium, OWASP A06)
- **Evidence:** `Cargo.lock` pins older `time`, `indexmap`, `clap`, `rayon`,
  `half`, etc. for rustc-1.75 compatibility (ADR-0005). Older crates may lack
  later security patches; `ring` (via rustls) has had advisories historically.
- **Mitigation:** add `cargo audit`/`cargo deny` to CI (advisory + license
  gate); move the fleet toolchain forward so pins can be relaxed; track
  RUSTSEC advisories for `ring`/`rustls`.

### S-7 — PII in logs (Low, OWASP A09)
- **Evidence:** at `debug`, transaction spans carry `correlation_id` (not PII)
  and rule ids; SUPI appears in the SBI path but is not logged at info. The
  `pii-logging` feature gates cleartext identity rendering; default redacts.
- **Mitigation:** ensure `debug` is not the production level; confirm no rule
  logs raw `vars`. Current posture is acceptable.

### S-8 — Admin/metrics exposure (Medium, OWASP A01)
- **Evidence:** `deploy/k8s/configmap.yaml` binds admin to `0.0.0.0:8080`;
  `deploy/cdot/config.yaml` binds `127.0.0.1`. On 0.0.0.0 without the
  NetworkPolicy, the admin API is reachable cluster-wide (JWT still required,
  so not open, but a larger surface).
- **Mitigation:** keep the NetworkPolicy mandatory; prefer binding admin to a
  pod-internal interface and exposing via an authenticated ingress only.

## 4.4 Injection / web-class checks (mostly N/A, stated)

| Class | Applicability | Verdict |
|---|---|---|
| SQL injection | No SQL/DB in the IWF | N/A |
| Command injection | No shell exec from request data | None found |
| Path traversal | SBI path built from AVP values via templates | **Low** — values are NF identifiers; percent-encoded for query; path segments are not sanitised against `..`. Recommend validating extracted identity vars against their newtype format before templating. |
| XSS / CSRF | No HTML UI; admin is a JSON/JWT API | N/A |
| SSRF | SBI targets come from NRF discovery, not user input | Low — discovery is trusted; ensure NRF is authenticated (mTLS) |
| Unsafe deserialization | serde_json/yaml/toml only; no native deser | Low — `deny_unknown_fields` on config/rules |

**Path-traversal note (actionable):** `engine.rs` substitutes extracted AVP
values directly into the SBI path. Today rules use IMSI/IMPI which the
mappings validate, but a future rule could place an unvalidated `{var}` into a
path. Recommend: run extracted vars destined for path segments through the
relevant `iwf-core` identity validator, or percent-encode path segments too.

## 4.5 Cryptography review

- **TLS**: 1.3-only via rustls (`iwf-security::tls`) — modern, no downgrade.
  Not yet wired (S-1).
- **JWT**: RS256 (prod) / HS256 (lab) via `jsonwebtoken`; 5 s leeway; aud/exp
  enforced. Sound.
- **5G-AKA material**: handled as opaque `Bytes`, length-validated, never
  logged. The IWF does not perform crypto on vectors (it relays AUSF output).
