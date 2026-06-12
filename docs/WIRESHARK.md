# Checking IWF traffic in Wireshark

All IWF↔Open5GS traffic on 192.168.179.39 is on **loopback** (`127.0.0.x`)
and **cleartext** (no TLS), so Wireshark decodes everything. You only need to:
capture on the `lo` interface, and tell Wireshark that port **7777 is HTTP/2**
(it's a non-standard port, so it won't auto-detect).

## What's where

| Traffic | Endpoint | Protocol | Wireshark filter |
|---|---|---|---|
| Cx (loadgen ↔ IWF) | `127.0.0.99:3868` | Diameter | `diameter` |
| SBA: IWF → NRF | `127.0.0.10:7777` | HTTP/2 (h2c) | `http2` |
| SBA: IWF → UDM | `127.0.0.12:7777` | HTTP/2 (h2c) | `http2` |

---

## Method 1 — Capture on the host, open in Wireshark on your laptop (recommended)

```bash
# On 192.168.179.39: capture Diameter + SBI on loopback
tcpdump -i lo -w /tmp/iwf.pcap 'tcp port 3868 or tcp port 7777' &
TPID=$!

# generate traffic
/opt/CDOT-iwf/bin/cdot_iwf start
/opt/CDOT-iwf/bin/loadgen 127.0.0.99:3868 --connections 1 --count 1 --seconds 5

kill $TPID          # stop capture

# From your laptop: copy the file off
scp root@192.168.179.39:/tmp/iwf.pcap .
```
Open `iwf.pcap` in Wireshark. **Important one-time setup for the SBA side:**
Right-click any packet on port 7777 → **Decode As…** → set *Current* =
**HTTP2** (or Analyze ▸ Decode As ▸ add `TCP port 7777 → HTTP2`). Diameter on
3868 is auto-detected.

## Method 2 — Wireshark GUI directly on the host

```bash
ssh -X root@192.168.179.39      # X-forwarding, or use the console
wireshark &
```
- Capture interface: **lo**
- Capture filter: `tcp port 3868 or tcp port 7777`
- After capture: Decode As port 7777 → HTTP2 (as above).

## Method 3 — tshark (CLI, no GUI needed)

```bash
# Diameter (Cx) summary: command code, request flag, app id, result code
tshark -r /tmp/iwf.pcap -d tcp.port==7777,http2 -Y diameter \
  -T fields -e frame.number -e diameter.cmd.code -e diameter.flags.request \
  -e diameter.applicationId -e diameter.Result-Code

# SBA HTTP/2 requests/responses
tshark -r /tmp/iwf.pcap -d tcp.port==7777,http2 -Y http2.headers \
  -T fields -e frame.number -e ip.dst -e http2.headers.method \
  -e http2.headers.path -e http2.headers.status
```
(`-d tcp.port==7777,http2` is the CLI form of "Decode As HTTP2".)

---

## Useful display filters

| Goal | Filter |
|---|---|
| All Cx | `diameter.applicationId == 16777216` |
| Just UAR | `diameter.cmd.code == 300` |
| Successful answers | `diameter.Result-Code == 2001` |
| The UDM SDM call | `http2.headers.path contains "am-data"` |
| All UDM traffic | `ip.addr == 127.0.0.12 && http2` |
| All NRF traffic | `ip.addr == 127.0.0.10 && http2` |
| One subscriber | `http2.headers.path contains "999700000000001"` |

To follow the JSON body of a UDM response: select the UDM `200` packet →
right-click → **Follow ▸ HTTP/2 Stream**.

---

## What a single call looks like (verified capture, 2026-06-11)

Diameter (port 3868):
```
frame  cmd  req  app        result
83     257  1               -        CER  (loadgen -> IWF)
85     257  0               2001     CEA
87     300  1    16777216   -        UAR  (Cx request)
152    300  0    16777216   2001     UAA  (success answer)
```

SBA HTTP/2 (port 7777) — the IWF's call to the Open5GS UDM:
```
frame 111  127.0.0.1 -> 127.0.0.12  GET /nudm-sdm/v2/imsi-999700000000001/am-data?plmn-id=%7B...%7D
frame 148  127.0.0.12 -> 127.0.0.1  :status 200
```
UDM response body (cleartext JSON):
```json
{"subscribedUeAmbr":{"uplink":"1000000 Kbps","downlink":"1000000 Kbps"},
 "nssai":{"defaultSingleNssais":[{"sst":1}]}}
```
You also see the NRF registration (`PUT /nnrf-nfm/v1/nf-instances/<uuid>` →
`201`) at startup, periodic heartbeats (`PATCH` → `204`), and the UDM fanning
out to the UDR (`/nudr-dr/...`) behind the scenes.
```
