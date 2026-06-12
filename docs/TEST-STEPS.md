# IWF — Simple Test Steps (Open5GS @ 192.168.179.39)

Plain steps to **run**, **test**, and **verify** the IWF talking to the
Open5GS UDM. Already built at `/opt/iwf` on the host. Copy-paste each block.

Login:  `ssh root@<open5gs-host>`  (use your host's credentials)

---

## STEP 0 — One-time facts (already done, here for reference)

| Thing | Value |
|---|---|
| Host | 192.168.179.39 (Open5GS installed) |
| IWF binary | `/opt/iwf/target/release/iwf-node` |
| Load test tool | `/opt/iwf/target/release/loadgen` |
| Config | `/etc/iwf/config.yaml` |
| Rules | `/etc/iwf/rules.yaml` |
| Test subscriber | IMSI `999700000000001`, PLMN MCC 999 / MNC 70 |
| NRF | `127.0.0.10:7777`   UDM | `127.0.0.12:7777` |
| IWF Diameter | `127.0.0.99:3868`   IWF metrics | `127.0.0.1:9090` |

---

## STEP 1 — Check Open5GS is up

```bash
systemctl is-active open5gs-nrfd open5gs-udmd
```
Expect: `active` `active`.

Check the UDM answers for the test subscriber (proves Open5GS itself works):
```bash
curl -s --http2-prior-knowledge \
 'http://127.0.0.12:7777/nudm-sdm/v2/imsi-999700000000001/am-data?plmn-id=%7B%22mcc%22%3A%22999%22%2C%22mnc%22%3A%2270%22%7D' \
 -w '\nHTTP=%{http_code}\n'
```
Expect: a JSON line ending with `HTTP=200`.
If not 200 → fix the subscriber in Open5GS first (Step 7).

---

## STEP 2 — Run the IWF

```bash
pkill -x iwf-node 2>/dev/null; sleep 1
cd /opt/iwf
setsid env \
  IWF_CONFIG=/etc/iwf/config.yaml \
  IWF_ADMIN_JWT_SECRET=dev-secret \
  IWF_NRF_REQUESTER_NF_TYPE=AUSF \
  IWF_LOG_LEVEL=info \
  ./target/release/iwf-node > /var/log/iwf.log 2>&1 < /dev/null &
sleep 4
echo "running pid: $(pgrep -x iwf-node)"
```
Expect: a process id printed.

⚠️ The 3 env vars matter:
- `IWF_NRF_REQUESTER_NF_TYPE=AUSF` — Open5GS only lets AUSF/AMF/SMF/SCP find the UDM.
- `IWF_ADMIN_JWT_SECRET` — required or it won't start.
- (do NOT set `IWF_SBA_HTTP1` — Open5GS needs HTTP/2.)

---

## STEP 3 — Verify it registered with the NRF

```bash
grep -E 'IWF up|registered with NRF' /var/log/iwf.log
```
Expect two lines: `IWF up ... listen 127.0.0.99:3868` and `registered with NRF`.

---

## STEP 4 — Run the test (send Cx traffic)

```bash
/opt/iwf/target/release/loadgen 127.0.0.99:3868 --tps 100 --connections 4 --seconds 6
```
Expect last lines like:
```
sent=604 answered=604 errors=0 achieved_tps=93
latency p50=7.7ms p95=10ms p99=15.2ms p999=19.8ms
```
✅ `answered == sent` and `errors=0`.

---

## STEP 5 — Verify the IWF actually called the Open5GS UDM

```bash
echo '--- IWF -> UDM calls (want http_status=200) ---'
curl -s http://127.0.0.1:9090/metrics | grep '^iwf_sba_requests_total'

echo '--- Cx UAR answers (want result_code=2001) ---'
curl -s http://127.0.0.1:9090/metrics | grep '^iwf_diameter_requests_total' | grep UAR
```
Expect:
```
iwf_sba_requests_total{http_status="200",nf_type="UDM",operation="Get /nudm-sdm/v2/{id}/am-data"} 604
iwf_diameter_requests_total{command="UAR",interface="cx",result_code="2001"} 604
```

**This is the proof:** 604 HTTP-200 calls to the UDM, 604 Diameter UARs answered SUCCESS (2001).

---

## STEP 6 — Stop the IWF (graceful)

```bash
kill -TERM $(pgrep -x iwf-node); sleep 2
pgrep -x iwf-node >/dev/null && echo "still running" || echo "stopped cleanly"
```
Expect: `stopped cleanly`. (Drains in-flight, deregisters from NRF, exits.)

---

## STEP 7 — (Optional) Add / check the test subscriber in Open5GS

If Step 1's UDM curl was not 200, add the subscriber.

Web UI:  `http://192.168.179.39:9999`  (admin / 1423) → add IMSI
`999700000000001` with a slice/APN. Or via Mongo:
```bash
mongosh open5gs --quiet --eval 'db.subscribers.find({},{imsi:1,_id:0}).toArray()'
```
Then re-run Step 1.

---

## What "PASS" looks like (the whole test in one glance)

1. Step 1 UDM curl → `HTTP=200`
2. Step 3 → `registered with NRF`
3. Step 4 → `answered == sent, errors=0`
4. Step 5 → `iwf_sba_requests_total{http_status="200",nf_type="UDM"...}` non-zero
   AND `iwf_diameter_requests_total{command="UAR"...result_code="2001"}` matches
5. Step 6 → `stopped cleanly`

---

## Quick troubleshooting

| You see | Meaning | Fix |
|---|---|---|
| UAR `result_code="5012"` and NO `iwf_sba_requests_total` line | rule/translation failed before calling UDM | check `/etc/iwf/rules.yaml` has **`plmn-id: "{{...}}"`** (double braces) |
| UAR `result_code="3002"` | UDM not reachable / not discovered | ensure `IWF_NRF_REQUESTER_NF_TYPE=AUSF`; check `open5gs-udmd` is active |
| UAR `result_code="5001"` | subscriber unknown | provision IMSI 999700000000001 (Step 7) |
| node won't start, log says JWT | secret missing | set `IWF_ADMIN_JWT_SECRET=...` |
| `nrf transport: client error` | talking HTTP/1.1 to HTTP/2 NRF | make sure `IWF_SBA_HTTP1` is NOT set |
| `heartbeat failed ... 400` | wrong PATCH content-type (old build) | rebuild from current source (`cargo build --release -p iwf-node`) |

---

## One-shot copy-paste (run + test + verify + stop)

```bash
pkill -x iwf-node 2>/dev/null; sleep 1; cd /opt/iwf
setsid env IWF_CONFIG=/etc/iwf/config.yaml IWF_ADMIN_JWT_SECRET=dev-secret \
  IWF_NRF_REQUESTER_NF_TYPE=AUSF IWF_LOG_LEVEL=info \
  ./target/release/iwf-node > /var/log/iwf.log 2>&1 < /dev/null &
sleep 4
grep -E 'registered with NRF' /var/log/iwf.log
./target/release/loadgen 127.0.0.99:3868 --tps 100 --connections 4 --seconds 6 | tail -2
curl -s http://127.0.0.1:9090/metrics | grep '^iwf_sba_requests_total'
curl -s http://127.0.0.1:9090/metrics | grep '^iwf_diameter_requests_total' | grep UAR
kill -TERM $(pgrep -x iwf-node); sleep 2
pgrep -x iwf-node >/dev/null && echo "still running" || echo "stopped cleanly"
```
