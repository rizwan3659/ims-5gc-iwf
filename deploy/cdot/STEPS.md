# CDOT-iwf — Compile, Build, Deploy & Test Steps

Two environments, kept separate:

* **Compile/build environment** — has the source tree + Rust toolchain.
* **Running environment** — has **only** `CDOT-iwf/{bin,etc,lib,log,run}`
  (binary + config + libraries; **no source code**).

On 192.168.179.39 both happen to be the same machine, in different dirs:
source/build at `/opt/iwf`, runtime install at `/opt/CDOT-iwf`.

Runtime layout produced by these scripts:
```
/opt/CDOT-iwf/
├── bin/   cdot_iwf  (start|stop|restart|status)   ← control script
│           iwf-node  (the daemon)
│           loadgen   (test client)
├── etc/   config.yaml   rules.yaml   cdot_iwf.env  ← all configuration
├── lib/   libgcc_s.so.1                            ← bundled libraries
├── log/   cdot_iwf.log                             ← all logs
└── run/   cdot_iwf.pid
```

---

## A. COMPILE & BUILD  (build environment)

```bash
# 1. Get the source onto the build host (once).
#    e.g. from your workstation:
rsync -az --exclude target/ iwf/ root@192.168.179.39:/opt/iwf/

# 2. Install Rust if absent (build host only).
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# 3. Compile (release).
cd /opt/iwf
bash deploy/cdot/build.sh
#   -> target/release/iwf-node, target/release/loadgen
```

## B. PACKAGE  (build environment — assemble the runtime tree, no source)

```bash
cd /opt/iwf
bash deploy/cdot/package.sh
#   -> /tmp/CDOT-iwf.tgz  (bin/ etc/ lib/ log/ run/, NO source)
```

## C. DEPLOY  (push to the running environment)

Same machine (install locally):
```bash
sudo tar xzf /tmp/CDOT-iwf.tgz -C /opt          # -> /opt/CDOT-iwf
```

Different machine (from the build host):
```bash
# plain ssh/key auth:
bash deploy/cdot/deploy.sh root@<run-host> /opt
# password auth:
SSHPASS='...' sshpass -e bash -c \
  'scp /tmp/CDOT-iwf.tgz root@<run-host>:/tmp/ && \
   ssh root@<run-host> "tar xzf /tmp/CDOT-iwf.tgz -C /opt"'
```

## D. CONFIGURE  (running environment — edit, no rebuild)

Edit files under `/opt/CDOT-iwf/etc/`:
* `cdot_iwf.env` — `IWF_ADMIN_JWT_SECRET` (change it!), `IWF_NRF_REQUESTER_NF_TYPE`
  (use `AUSF` for Open5GS), `IWF_LOG_LEVEL`.
* `config.yaml` — NRF URI, listen addresses, timeouts.
* `rules.yaml`  — translation rules (subscriber IMSI / PLMN).

> Open5GS reminders baked into the defaults: requester type `AUSF`,
> `IWF_SBA_HTTP1` unset (HTTP/2), and JSON braces in rule values escaped `{{ }}`.

## E. RUN

```bash
/opt/CDOT-iwf/bin/cdot_iwf start
/opt/CDOT-iwf/bin/cdot_iwf status
/opt/CDOT-iwf/bin/cdot_iwf stop
/opt/CDOT-iwf/bin/cdot_iwf restart
```
`start` returns 0 on success; `status` exits 0 running / 3 stopped (LSB).

## F. VERIFY  (the deployment actually talks to the Open5GS UDM)

```bash
# 1. Registered with NRF?
grep 'registered with NRF' /opt/CDOT-iwf/log/cdot_iwf.log

# 2. Drive Cx traffic.
/opt/CDOT-iwf/bin/loadgen 127.0.0.99:3868 --tps 100 --connections 4 --seconds 6
#    -> sent=604 answered=604 errors=0

# 3. Confirm UDM calls + success answers.
curl -s http://127.0.0.1:9090/metrics | grep '^iwf_sba_requests_total'
curl -s http://127.0.0.1:9090/metrics | grep '^iwf_diameter_requests_total' | grep UAR
```
**PASS** looks like:
```
iwf_sba_requests_total{http_status="200",nf_type="UDM",operation="Get /nudm-sdm/v2/{id}/am-data"} 604
iwf_diameter_requests_total{command="UAR",interface="cx",result_code="2001"} 604
```
(604 HTTP-200 calls to the Open5GS UDM; 604 Cx UARs answered SUCCESS.)

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `start` fails: `binding 127.0.0.1:8080: Address already in use` | a stray `iwf-node` is running: `pkill -x iwf-node`, then `start` |
| `start` fails: `binding ... 3868` | another Diameter app on that addr; change `diameter.listen` in `etc/config.yaml` |
| `status` says STOPPED right after `start` | read `log/cdot_iwf.log`; common: missing `IWF_ADMIN_JWT_SECRET` in `etc/cdot_iwf.env` |
| UAR `result_code="5012"` and no `iwf_sba_requests_total` | `etc/rules.yaml` `plmn-id` must use **double braces** `"{{...}}"` |
| UAR `result_code="3002"` | UDM not discovered — set `IWF_NRF_REQUESTER_NF_TYPE=AUSF` in `etc/cdot_iwf.env`, restart |
| UAR `result_code="5001"` | subscriber not provisioned in Open5GS UDR |
| `nrf transport: client error` | ensure `IWF_SBA_HTTP1` is **not** set (5GC SBI is HTTP/2) |

## Logs & files at a glance
* Logs:    `/opt/CDOT-iwf/log/cdot_iwf.log`
* Config:  `/opt/CDOT-iwf/etc/{config.yaml,rules.yaml,cdot_iwf.env}`
* PID:     `/opt/CDOT-iwf/run/cdot_iwf.pid`
* Control: `/opt/CDOT-iwf/bin/cdot_iwf`
