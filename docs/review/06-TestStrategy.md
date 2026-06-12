# 6. Test Strategy, Detailed Test Cases & Load Generation

## 6.1 Current test inventory (assessment)

| Layer | Where | Count / kind | Verdict |
|---|---|---|---|
| Unit | `#[cfg(test)]` in each module | ~110 | Strong; covers codec, FSM, routing, rules, breaker, retry, jwt, rbac, mappings |
| Property | `iwf-diameter/tests/proptest_roundtrip.rs` | 4 props | Excellent — codec round-trip + decoder-never-panics fuzz |
| Integration (in-proc mocks) | `iwf-discovery`, `iwf-sba`, `iwf-admin` tests | several | Good — Axum mock NFs, no docker needed |
| End-to-end | `iwf-node/tests/e2e.rs` | 1 (multi-assert) | Boots the real binary vs mock NRF/UDM/UDR over real TCP |
| Functional (deployed) | `deploy/cdot/tests.sh` | 7 cases / 14 asserts | Runs against live Open5GS |
| Bench | `iwf-benchmark/benches/codec.rs` | 3 | Codec regression gate |
| **Total automated** | | **129 cargo tests, all green** | |

**Coverage assessment:** high for pure logic (codec, FSM, rules, mappings,
security primitives). A formal line-coverage number is **not yet enforced** —
the `cargo-tarpaulin` CI job is present but marked informational because it
needs a newer toolchain than the pinned rustc 1.75. *Estimated* coverage of
the library crates is high (most public functions have direct tests); the
gaps are integration-level (below).

## 6.2 Missing scenarios / gaps

| Gap | Risk | Add |
|---|---|---|
| Diameter MAR→AUSF flow e2e | Auth path unverified end-to-end | T-INT-03 |
| Sh PUR (PUT, idempotent) e2e | Update path | T-INT-04 |
| Unknown-subscriber (UDM 404 → 5001) live | Error mapping vs real core | T-FN-07 / T-E2E-02 |
| Circuit-breaker trip under NF outage e2e | Reliability | T-INT-05 |
| NRF-down → cached discovery → recovery | Resilience | T-INT-06 |
| Ingress shedding (3004) under overload | Backpressure | T-PERF-03 |
| TLS/mTLS handshake (once wired) | Security | T-SEC-* (pending D-01) |
| Malformed Diameter from a real peer (fuzz over the socket) | Robustness | T-SEC-02 |
| Graceful drain with in-flight to a slow NF | Zero-downtime upgrade | T-E2E-03 |
| Config/rules hot-reload while serving | No-restart ops | T-INT-07 |

## 6.3 Mocking strategy review

- In-process **Axum** mocks for NRF/UDM/UDR (no docker-compose) — fast,
  hermetic, correct choice for `cargo test`.
- `mock5gc` binary for load tests — constant-time responses so the IWF, not
  the mock, is the bottleneck. Good.
- **Risk:** the Axum mocks speak HTTP/1.1, so tests set `IWF_SBA_HTTP1=1`; the
  *real* path is h2c. The h2c path is covered only by the live Open5GS run and
  the `with_http2` unit toggle. Recommend one integration test against an
  h2c mock (hyper server with `http2_only`) to cover the production transport
  in CI. *(gap)*

---

## 6.4 Detailed test cases

Notation: **T-FN** functional, **T-INT** integration, **T-E2E** end-to-end,
**T-REG** regression, **T-PERF** performance, **T-SEC** security. Each:
*Pre / Steps / Expected / Oracle*.

### Functional — positive

**T-FN-01 Cx UAR → UAA success**
- Pre: rule maps UAR→UDM SDM; subscriber provisioned.
- Steps: send UAR(User-Name, Public-Identity).
- Expected: UAA, Result-Code 2001; Server-Name present if UDM returns one.
- Oracle: `engine::tests::uar_200_yields_uaa_success_and_correct_sbi_request`; live `tests.sh` TEST 02.

**T-FN-02 Cx MAR → MAA with SIP-Auth-Data-Item**
- Pre: AUSF returns `Av5gAka`.
- Steps: MAR(User-Name).
- Expected: MAA 2001; `SIP-Auth-Data-Item` group with `SIP-Authenticate`
  (RAND‖AUTN, 32 octets) and `SIP-Authorization` (XRES*).
- Oracle: `plugin::tests::maa_success_builds_auth_data_item`.

**T-FN-03 Sh UDR → UDA with User-Data**
- Expected: UDA 2001 carrying repository payload in `User-Data` AVP.
- Oracle: e2e `cx_and_sh_flows_end_to_end`.

### Functional — negative / error

**T-FN-04 Missing mandatory AVP**
- Steps: UAR without User-Name (required extract).
- Expected: `CoreError::MissingElement` → answer Result-Code 5005.
- Oracle: `engine::tests::missing_required_avp_is_rejected`.

**T-FN-05 No rule for command**
- Steps: send PPR (no rule).
- Expected: `CoreError::NoRule` → 3001 COMMAND_UNSUPPORTED.
- Oracle: `engine::tests::unknown_command_has_no_rule`; e2e asserts 3001.

**T-FN-06 Unmapped HTTP status, no default**
- Steps: rule without `default`; NF returns 418.
- Expected: translation error → 5012.
- Oracle: `engine::tests::unmapped_status_without_default_fails_closed`.

**T-FN-07 Unknown subscriber (UDM 404 → 5001)**
- Steps: query a non-provisioned IMSI.
- Expected: Experimental-Result-Code 5001 USER_UNKNOWN.
- Oracle: `plugin::tests::user_unknown_uses_experimental_result`; add live
  variant (point rule at a missing IMSI).

### Functional — boundary

**T-FN-08 AVP codec boundaries** — undersized length, length past buffer,
vendor bit without vendor-id space, 32-bit padding, max group depth.
- Oracle: `avp::tests::*`, `proptest_roundtrip::*`.

**T-FN-09 Identity validation boundaries** — IMSI 5..15 digits, IMPI NAI
form, MSISDN TBCD odd/even length.
- Oracle: `identity::tests::*`, `mapping::tests::tbcd_round_trip`.

**T-FN-10 A/B rollout bucketing** — split 30/70 is stable per End-to-End id.
- Oracle: `rule::tests::ab_rollout_buckets_split_traffic`.

### Integration (add these — see §6.6 for code)

- **T-INT-01** discovery cache: 2nd resolve served from cache (no NRF hit). *(exists)*
- **T-INT-02** discovery failure → mark unhealthy → re-query. *(exists)*
- **T-INT-03** MAR→AUSF end-to-end against mock AUSF. *(add)*
- **T-INT-04** Sh PUR (PUT) idempotent update against mock UDR. *(add)*
- **T-INT-05** circuit breaker opens after N 5xx; requests then fail fast. *(add)*
- **T-INT-06** NRF down → serve cached endpoints until TTL → recover. *(add)*
- **T-INT-07** rules hot-reload via admin PUT while serving; new rule active. *(add)*

### End-to-end

- **T-E2E-01** Cx+Sh happy path + DWR/DWA + unsupported cmd. *(exists)*
- **T-E2E-02** unknown subscriber → 5001 (live). *(add, live)*
- **T-E2E-03** drain with in-flight to a deliberately slow NF; verify no lost
  answers within drain budget, then clean exit. *(add)*

### Regression (lock in the fixed bugs)

- **T-REG-01** h2c: NRF client must speak HTTP/2 (D-fixed-1).
- **T-REG-02** discovery resolves `ipEndPoints` when `apiPrefix` absent
  (D-fixed-4). *(exists: `cache::tests::discovery_populates_and_caches`)*
- **T-REG-03** `{{`/`}}` brace escaping in templates (D-fixed-3). *(exists:
  `engine::tests::substitution_escapes_braces_for_json_values`)*
- **T-REG-04** heartbeat uses `application/json-patch+json` (D-fixed-5). *(add)*
- **T-REG-05** bounded shutdown — process exits within budget even with
  stranded in-flight (D-fixed-6). *(add, e2e)*

### Performance

- **T-PERF-01** codec micro-bench regression (decode/encode). *(exists)*
- **T-PERF-02** sustained TPS vs mock5gc; assert p99 + 0 errors (see §6.5).
- **T-PERF-03** ingress shedding: drive above `max_in_flight`; assert excess
  answered 3004 and p99 of admitted traffic stays within SLO. *(add)*
- **T-PERF-04** 72-hour soak: flat RSS, sawtooth active-sessions, no fd growth.

### Security

- **T-SEC-01** admin RBAC matrix: read-only cannot PUT rules / set log-level;
  provisioning cannot set log-level; bad/expired/wrong-aud JWT rejected.
  *(exists: `admin::tests::*`, `jwt::tests::*`)*
- **T-SEC-02** socket fuzz: feed random bytes to the Diameter listener; assert
  the process never panics and the connection is closed. *(add)*
- **T-SEC-03** (post D-01) mTLS required: connection without a client cert is
  rejected; TLS < 1.3 refused.

---

## 6.5 HOW TO GENERATE LOAD

The bundled `loadgen` is a real Diameter client: it performs CER/CEA per
connection, then drives Cx UARs at a paced rate, reporting achieved TPS and
client-side latency percentiles. `mock5gc` provides a fast NRF+UDM so the IWF
is the bottleneck.

### 6.5.1 Quick single call (functional)
```bash
loadgen 127.0.0.99:3868 --connections 1 --count 1 --seconds 5
# exactly one UAR; expect: sent=1 answered=1 errors=0
```

### 6.5.2 Steady load (one generator)
```bash
loadgen <iwf-host>:3868 --tps 25000 --connections 16 --seconds 300
# prints: sent=.. answered=.. errors=0 achieved_tps=..
#         latency p50=.. p95=.. p99=.. p999=..
```
Flags:
- `--tps N` aggregate target rate (split across connections).
- `--connections N` parallel Diameter connections (each does CER/CEA once).
- `--seconds N` test duration.
- `--count N` send exactly N total then stop (overrides duration for short
  deterministic runs).

### 6.5.3 100k TPS acceptance (multiple generators)
A single generator is itself CPU-bound; for the 100k target run **4 generator
processes/pods at 25k each** against a 4–6 pod IWF deployment:
```bash
# on 4 hosts (or 4 shells), simultaneously:
loadgen <iwf-vip>:3868 --tps 25000 --connections 16 --seconds 300
```
Stand up the fast mock core first so the NF isn't the bottleneck:
```bash
mock5gc 0.0.0.0:18080 0.0.0.0:18081     # NRF on :18080, UDM on :18081
# point the IWF config sba.nrf_uri at http://<mock-host>:18080
```

### 6.5.4 What "pass" looks like
Aggregate across generators:
- `sum(achieved_tps) ≥ 100000`
- each generator's `errors=0` and `answered==sent` (≥ 99.9%)
- IWF-side **internal** p99 < 5 ms:
  ```bash
  curl -s http://<iwf>:9090/metrics \
    | grep 'iwf_diameter_latency_seconds_bucket' | grep 'le="0.005"'
  # the le="0.005" bucket should hold ≥ 99% of the _count
  ```
- generator (end-to-end) p99 < 20 ms.

### 6.5.5 Reading the histogram (internal latency)
```bash
# fraction of UAR transactions completed within 5 ms:
M=http://127.0.0.1:9090/metrics
le5=$(curl -s $M | awk -F' ' '/iwf_diameter_latency_seconds_bucket\{command="UAR".*le="0.005"/{print $NF}')
tot=$(curl -s $M | awk -F' ' '/iwf_diameter_latency_seconds_count\{command="UAR"/{print $NF}')
echo "within 5ms: $le5 / $tot"
```
(Note: metric values are the **last** field — `$NF` — because the `operation`
label can contain a space; see D-08.)

### 6.5.6 Codec micro-benchmarks (CPU headroom)
```bash
cargo bench -p iwf-benchmark        # decode≈353ns, encode≈90ns per op
```

### 6.5.7 Overload / backpressure test
Drive above the node's `max_in_flight` (or starve the NF) and confirm the
excess is shed as `DIAMETER_TOO_BUSY` (3004) rather than latency-bloating:
```bash
loadgen <iwf>:3868 --tps 200000 --connections 64 --seconds 30
curl -s http://<iwf>:9090/metrics | grep 'result_code="3004"'   # should be > 0
# and the admitted traffic's p99 should stay within SLO
```

---

## 6.6 Generated test code (additions)

These compile against the existing framework (`tokio::test` + Axum mocks).
Place under the indicated crate's tests.

### T-INT-05 — circuit breaker opens after repeated 5xx
`iwf-sba/src/client.rs` (add to `mod tests`):
```rust
#[tokio::test]
async fn breaker_opens_after_repeated_5xx_then_fails_fast() {
    use axum::routing::get;
    let app = axum::Router::new()
        .route("/nudm-sdm/v2/:id/am-data", get(|| async {
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve"); });

    let client = client_for(&format!("http://{addr}"), 1); // breaker threshold default 5
    let req = sample_request();
    // Drive enough 5xx to trip the breaker (threshold consecutive failures).
    let mut opened = false;
    for _ in 0..10 {
        let r = client.send(req.clone()).await;
        // 5xx is returned to rules as Ok(503) until breaker trips, then NfUnavailable.
        if matches!(r, Err(iwf_core::error::CoreError::NfUnavailable { .. })) { opened = true; break; }
    }
    assert!(opened, "breaker should open and fail fast after repeated 5xx");
}
```

### T-REG-04 — heartbeat content-type is json-patch
`iwf-discovery/src/heartbeat.rs` (add to `mod tests`): assert the mock NRF
receives `content-type: application/json-patch+json` on PATCH.
```rust
// In the mock router's .patch handler, capture headers and assert:
//   headers.get("content-type") == Some("application/json-patch+json")
// then drive one heartbeat and await the assertion via a oneshot/Notify.
```

### T-SEC-02 — Diameter socket fuzz (never panics)
`iwf-node/tests/` (new integration test): connect to the running listener,
send random byte blobs of varying lengths, assert the process stays up
(subsequent valid CER still succeeds) and the fuzzed connections are closed.
```rust
// for _ in 0..1000 { let mut s = TcpStream::connect(addr).await?;
//   let n = rand_len(); let buf: Vec<u8> = (0..n).map(|_| rand::random()).collect();
//   let _ = s.write_all(&buf).await; }  // then assert a fresh CER/CEA still works
```

### T-E2E-03 — drain with in-flight to a slow NF
Extend `e2e.rs`: point a rule at a mock UDM that sleeps ~2 s; send a burst;
send SIGTERM; assert in-flight answers arrive (or are accounted) within the
drain budget and the process exits cleanly.
```rust
// slow mock: get(|| async { tokio::time::sleep(Duration::from_secs(2)).await; Json(...) })
// burst N UARs; kill -TERM; poll for process exit within drain_timeout_s + margin.
```

> Run all existing + new tests: `cargo test --workspace --locked`.
> Run the deployed functional suite: `/opt/CDOT-iwf/bin/tests.sh`.
