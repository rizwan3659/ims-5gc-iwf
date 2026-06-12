# Deploying the IWF against Open5GS — manual, step-by-step

This guide takes you from source to a running IWF that **registers with the
Open5GS NRF, discovers the Open5GS UDM, and answers a Diameter Cx request by
calling that UDM**. Every step is a copy-pasteable command. Target host:
`192.168.179.39` (Open5GS already installed).

> **Verified end-to-end on 2026-06-11** against Open5GS on this host: 402/402
> Cx UARs answered `2001`, each driving an HTTP/2 `GET /nudm-sdm/v2/{supi}/am-data`
> to the Open5GS UDM that returned `200`. The exact settings that made it work
> are baked into the steps below; the "gotchas" are real findings, not theory:
> 1. Run on the Open5GS host (SBI binds to `127.0.0.x`).
> 2. SBI is HTTP/2 cleartext — leave `IWF_SBA_HTTP1` **unset**.
> 3. Open5GS NRF rejects discovery from `requester-nf-type` AF/NEF/IWF; use
>    **`IWF_NRF_REQUESTER_NF_TYPE=AUSF`** (AMF/AUSF/SMF/SCP are accepted).
> 4. Open5GS NRF rejects an `nfType: "IWF"` *registration*; register as **`AF`**
>    (§4 patch).
> 5. The UDM advertises its address in `nfServices[].ipEndPoints`, not
>    `apiPrefix` — the IWF resolves both (handled in code, no action needed).
> 6. In rules, escape literal JSON braces in query/body values as `{{`/`}}`
>    (e.g. the `plmn-id` value) so they aren't read as `{var}` placeholders.

> Conventions: `[host]$` = the Open5GS machine (192.168.179.39),
> `[local]$` = your workstation. PLMN in examples is **MCC 001 / MNC 01** and
> test subscriber IMSI **001011234567890** — change to match your Open5GS.

---

## 0. Decide the topology

The IWF must reach Open5GS SBI (NRF + UDM). Open5GS binds each NF's SBI to a
**loopback** address by default (`127.0.0.x:7777`). The simplest, lowest-risk
choice is therefore:

> **Run the IWF *on* the Open5GS host (192.168.179.39).** It then reaches the
> NRF at `http://127.0.0.10:7777` with no Open5GS reconfiguration.

Cross-host deployment is possible but requires rebinding every Open5GS SBI to
a routable address — covered in §9. Use same-host first.

---

## 1. Prerequisites on the Open5GS host

```bash
[host]$ # Rust toolchain (>= 1.75). rustup is easiest:
[host]$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
[host]$ source "$HOME/.cargo/env"
[host]$ rustc --version            # expect 1.75 or newer

[host]$ # Build deps
[host]$ sudo apt-get update && sudo apt-get install -y build-essential pkg-config git

[host]$ # Confirm Open5GS 5GC NFs are running (NRF + UDM + UDR are what we need)
[host]$ systemctl list-units 'open5gs-*' --no-pager | grep -E 'nrf|udm|udr|ausf'
[host]$ sudo ss -tlnp | grep 7777     # SBI listeners (you should see 127.0.0.x:7777)
```

Note the NRF's SBI address from `/etc/open5gs/nrf.yaml` (default `127.0.0.10`,
port `7777`). Confirm:

```bash
[host]$ grep -A4 'sbi:' /etc/open5gs/nrf.yaml | head -8
[host]$ grep -A4 'sbi:' /etc/open5gs/udm.yaml | head -8
```

---

## 2. Get the source onto the host

```bash
[local]$ # from the directory that contains the iwf/ workspace
[local]$ rsync -az --exclude target/ iwf/ root@192.168.179.39:/opt/iwf/
# (or: git clone <your-repo> /opt/iwf on the host)
```

---

## 3. Build the IWF (release)

```bash
[host]$ cd /opt/iwf
[host]$ cargo build --release --locked -p iwf-node -p iwf-benchmark
[host]$ ls -l target/release/iwf-node target/release/loadgen target/release/mock5gc
```

> If your host rustc is **older than 1.75**, the pinned `Cargo.lock` is built
> for 1.75 and will compile cleanly. If it is *much* newer and resolution
> complains, build with the lock as-is (`--locked`); do **not** run
> `cargo update` (see `docs/adr/0005-toolchain-and-workspace.md`).

---

## 4. Will Open5GS NRF accept NF type "IWF"?  (one-time check)

Two independent NF-type checks matter:

**(a) Discovery requester type** — set at runtime, no rebuild. Open5GS only
returns the UDM to requesters that legitimately consume it. Probe each:

```bash
[host]$ for r in IWF AF AUSF AMF SCP; do
          n=$(curl -sS --http2-prior-knowledge \
            "http://127.0.0.10:7777/nnrf-disc/v1/nf-instances?target-nf-type=UDM&requester-nf-type=$r" \
            | python3 -c 'import sys,json;print(len(json.load(sys.stdin).get("nfInstances",[])))' 2>/dev/null)
          echo "requester=$r -> UDM instances=$n"; done
# On this Open5GS: IWF/AF -> 0, AUSF/AMF/SCP -> 1.
```

Pick a requester type that returns ≥1 and pass it as
`IWF_NRF_REQUESTER_NF_TYPE` in §7 (we use **`AUSF`** — closest to the IWF's
Cx/MAR auth-consumer role). **No rebuild needed for this.**

**(b) Registration nfType** — the IWF registers itself as `nfType: "IWF"`.
Open5GS rejects unknown types on registration (the heartbeat/registration
PUT 4xxs). Register as `AF` instead — a one-line patch + rebuild:

```bash
[host]$ sed -i 's/nf_type: "IWF".to_owned()/nf_type: "AF".to_owned()/' \
     iwf-discovery/src/profile.rs
[host]$ cargo build --release --locked -p iwf-node
```

(Functionally the IWF is an application function to the 5GC; this only changes
the label it advertises. The discovery requester type from (a) is separate and
set via the env var — do **not** hardcode it here.)

---

## 5. Provision the test subscriber in Open5GS

The UDM only returns data for subscribers in its database. Provision the IMSI
the test will query (**001011234567890**), with the matching PLMN.

**Option A — Open5GS WebUI** (http://<host>:9999, default admin/1423):
add a subscriber with IMSI `001011234567890`, any key/OPc, and at least one
slice/APN so `am-data` is populated.

**Option B — CLI** (`open5gs-dbctl`):

```bash
[host]$ cd /opt/iwf   # or wherever; dbctl is usually on PATH after install
[host]$ open5gs-dbctl add 001011234567890 \
     465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA
[host]$ open5gs-dbctl showpretty | grep -A2 001011234567890
```

Verify the UDM answers for this subscriber (proves §5 + UDM health):

```bash
[host]$ curl -sS --http2-prior-knowledge \
   'http://127.0.0.12:7777/nudm-sdm/v2/imsi-001011234567890/am-data?plmn-id=%7B%22mcc%22%3A%22001%22%2C%22mnc%22%3A%2201%22%7D' \
   | head -c 400 ; echo
# Expect HTTP 200 with AccessAndMobilitySubscriptionData JSON.
# (127.0.0.12 is the Open5GS UDM default SBI address — confirm via §1.)
```

If this `curl` does not return 200, fix provisioning/PLMN **before** involving
the IWF — the IWF can only relay what the UDM returns.

---

## 6. Configure the IWF for Open5GS

```bash
[host]$ sudo mkdir -p /etc/iwf
[host]$ sudo cp /opt/iwf/config/rules-open5gs.yaml /etc/iwf/rules.yaml
[host]$ sudo tee /etc/iwf/config.yaml >/dev/null <<'YAML'
diameter:
  listen: "0.0.0.0:3868"
  origin_host: "iwf.epc.example.org"
  origin_realm: "epc.example.org"
  transaction_timeout_ms: 5000
  max_in_flight: 50000
sba:
  # Open5GS NRF SBI (confirm address/port from /etc/open5gs/nrf.yaml).
  nrf_uri: "http://127.0.0.10:7777"
  request_timeout_ms: 2000
  discovery_ttl_s: 300
admin:
  listen: "0.0.0.0:8080"
  metrics_listen: "0.0.0.0:9090"
  jwt_hs256_secret_env: "IWF_ADMIN_JWT_SECRET"
  jwt_audience: "iwf-admin"
rules_file: "/etc/iwf/rules.yaml"
drain_timeout_s: 30
YAML
```

Notes:
* `rules-open5gs.yaml` ships with the **smoke rule** enabled — it maps Cx UAR
  to `GET /nudm-sdm/v2/imsi-001011234567890/am-data`, so the stock `loadgen`
  drives a real UDM call with no client changes.
* **Do not set `IWF_SBA_HTTP1`** — leaving it unset makes the IWF speak h2c
  (HTTP/2 cleartext), which is what Open5GS SBI requires. (`IWF_SBA_HTTP1=1`
  is only for HTTP/1.1 test mocks.)
* No OAuth: with `IWF_OAUTH_CLIENT_ID` unset the IWF sends no bearer token.
  Open5GS SBI does not require OAuth2 by default. If your Open5GS enforces it,
  set `IWF_OAUTH_CLIENT_ID` / `IWF_OAUTH_CLIENT_SECRET` and the token endpoint.

---

## 7. Run the IWF and confirm NRF registration + discovery

```bash
[host]$ cd /opt/iwf
[host]$ export IWF_CONFIG=/etc/iwf/config.yaml
[host]$ export IWF_ADMIN_JWT_SECRET=dev-admin-secret   # lab HS256 secret
[host]$ export IWF_NRF_REQUESTER_NF_TYPE=AUSF          # §4(a): type the NRF lets discover UDM
[host]$ export IWF_LOG_LEVEL=info
[host]$ ./target/release/iwf-node
```

In the logs look for:
* `registered with NRF` — registration succeeded.
* The pod becomes **ready** once a Diameter peer connects (step 8). Until then
  `/readyz` is 503 by design.

Confirm registration from the NRF side:

```bash
[host]$ curl -sS --http2-prior-knowledge \
   "http://127.0.0.10:7777/nnrf-disc/v1/nf-instances?target-nf-type=AF&requester-nf-type=AF" \
   | python3 -m json.tool | grep -E 'nfInstanceId|nfType' | head
# (use target-nf-type=IWF if you did NOT apply the §4 patch)
```

Health/metrics:

```bash
[host]$ curl -s http://127.0.0.1:8080/healthz ; echo      # 200
[host]$ curl -s http://127.0.0.1:9090/metrics | grep -E 'iwf_peer_state|iwf_active_sessions'
```

---

## 8. Drive a Cx request → watch the IWF call the UDM

The bundled `loadgen` performs CER/CEA then sends Cx UARs. Run a short, low
rate first:

```bash
[host]$ ./target/release/loadgen 127.0.0.1:3868 --tps 50 --connections 2 --seconds 10
# Expect: answered == sent, errors=0, and low latency percentiles.
```

Confirm the call actually reached the Open5GS UDM (two independent views):

```bash
[host]$ # IWF view: SBA calls to UDM with HTTP 200.
[host]$ curl -s http://127.0.0.1:9090/metrics \
     | grep 'iwf_sba_requests_total{nf_type="UDM"'
[host]$ # Diameter view: UAR answered 2001 (success).
[host]$ curl -s http://127.0.0.1:9090/metrics \
     | grep 'iwf_diameter_requests_total{command="UAR"'
[host]$ # Open5GS view: UDM access log shows the SDM am-data GET.
[host]$ sudo journalctl -u open5gs-udmd --no-pager -n 30 | grep -i am-data
```

A single transaction, end to end, with full request/answer logging:

```bash
[host]$ IWF_LOG_LEVEL=debug ./target/release/iwf-node &
[host]$ ./target/release/loadgen 127.0.0.1:3868 --tps 1 --connections 1 --seconds 3
# In the IWF debug log you will see: rule match -> SBI GET to UDM ->
# map_response 200 -> UAA built with Result-Code 2001 (and Server-Name if the
# UDM payload carried one).
```

**Pass criteria for "communicating with the UDM":**
1. `iwf_sba_requests_total{nf_type="UDM",...,http_status="200"}` is non-zero.
2. `iwf_diameter_requests_total{command="UAR",...,result_code="2001"}` matches
   the requests you sent.
3. The Open5GS `udmd` journal shows the `am-data` GET for `imsi-001011234567890`.

(Provision a *different* IMSI and query it to see a `404` path map to
`Experimental-Result 5001 DIAMETER_ERROR_USER_UNKNOWN` — proves error mapping.)

---

## 9. (Optional) Cross-host: IWF on a different machine

If you must run the IWF elsewhere, expose Open5GS SBI on a routable address.
For each of NRF, UDM, UDR, AUSF edit `/etc/open5gs/<nf>.yaml`:

```yaml
sbi:
  server:
    - address: 192.168.179.39     # was 127.0.0.x
      port: 7777
  # NFs also need each other's new addresses; the NRF address is configured
  # in every NF's `sbi.client.nrf` / `scp` section — update those to
  # 192.168.179.39 too.
```

```bash
[host]$ sudo systemctl restart open5gs-nrfd open5gs-udmd open5gs-udrd open5gs-ausfd
```

Then set `sba.nrf_uri: "http://192.168.179.39:7777"` in the IWF config and open
the firewall for 7777 and 3868. (This changes Open5GS's own inter-NF wiring —
do it deliberately and revert if it disturbs the core.)

---

## 10. (Optional) Run the IWF as a systemd service

```bash
[host]$ sudo tee /etc/systemd/system/iwf.service >/dev/null <<'UNIT'
[Unit]
Description=IMS/5GC Interworking Function
After=network-online.target open5gs-nrfd.service
Wants=open5gs-nrfd.service

[Service]
Type=simple
Environment=IWF_CONFIG=/etc/iwf/config.yaml
Environment=IWF_LOG_LEVEL=info
Environment=IWF_ADMIN_JWT_SECRET=change-me
ExecStart=/opt/iwf/target/release/iwf-node
Restart=on-failure
# Match the drain budget so SIGTERM can complete gracefully.
TimeoutStopSec=45
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
[host]$ sudo systemctl daemon-reload && sudo systemctl enable --now iwf
[host]$ sudo journalctl -u iwf -f
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `nrf transport: client error` at startup | IWF talking HTTP/1.1 to h2c NRF, or wrong NRF address | Ensure `IWF_SBA_HTTP1` is **unset**; verify `nrf_uri` against `/etc/open5gs/nrf.yaml` |
| NRF registration rejected (4xx) | Open5GS validates `nfType` | Apply the §4 patch (advertise `AF`) and rebuild |
| Discovery returns 0 UDM instances | UDM not registered / different PLMN | `systemctl status open5gs-udmd`; check NRF has the UDM (`/nnrf-disc ... target-nf-type=UDM`) |
| UAR answered `5012` / `3002` | UDM unreachable or 5xx | Run the §5 `curl` directly against the UDM; check `udmd` logs |
| UAR answered `5001` (user unknown) | Subscriber/PLMN not provisioned, or wrong SUPI in the rule | Re-do §5; ensure the IMSI in `rules-open5gs.yaml` matches the provisioned one |
| UAR answered `3001` (command unsupported) | No rule matched the command/app | Confirm `loadgen` sends Cx UAR (app 16777216, cmd 300) and the rule trigger matches |
| `/readyz` stays 503 | No Diameter peer has completed CER/CEA yet | This is expected pre-traffic; it flips ready after the first peer connects |
| UDM returns 404 for the §5 curl | subscriber missing or `am-data` empty | Provision via WebUI/`open5gs-dbctl` with a slice/APN |

---

## What this exercises in the IWF

`loadgen` → **iwf-diameter** (CER/CEA, UAR decode, peer FSM) → **iwf-translation**
(rule match, AVP extract, build SBI request) → **iwf-sba** (h2c HTTP/2 to UDM,
breaker/retry) using **iwf-discovery** (NRF-resolved UDM endpoint, cached) →
**iwf-translation** plugin builds the UAA → back over **iwf-diameter**. NRF
registration/heartbeat run continuously in **iwf-discovery**; metrics in
**iwf-observability**; `/healthz`,`/readyz` in **iwf-admin**.
