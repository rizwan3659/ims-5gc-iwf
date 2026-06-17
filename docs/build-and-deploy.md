# Build on host & deploy to a remote server

How to compile the IWF on a build host, produce a runnable artifact, ship it
to a remote server, configure it, and bring it up. For the Open5GS-specific
integration walk-through (NRF quirks, subscriber provisioning, h2c) see
[`deploy-open5gs.md`](deploy-open5gs.md); for day-2 operations see
[`runbook.md`](runbook.md).

The deployable network function is a **single static-ish binary**:
`iwf-node` (the `iwf-node` crate is the only binary in the workspace).

---

## 0. Toolchain & host prerequisites

| Item | Value | Why |
|---|---|---|
| Build toolchain | **rustc 1.75** (`/usr/bin/rustc`) | the project MSRV; `Cargo.lock` is pinned for it (ADR-0005) |
| Lint toolchain | rustc/clippy 1.95 (`/snap/bin`) | the 1.75 install ships no clippy |
| Edition | 2021 | |
| Disk | ≥ ~10 GB free | a disk-full event mid-build corrupts `rmeta`; build with `CARGO_INCREMENTAL=0` |

> **Do not** run `cargo update`. Transitive crates are pinned with
> `--precise` for the 1.75 MSRV (indexmap, time, clap, rayon, half,
> crossbeam-*); a wholesale update breaks the build.

```bash
rustc --version            # expect 1.75.x
df -h .                    # confirm headroom before a release build
```

---

## 1. Compile & verify (build host)

```bash
cd /path/to/iwf

# Release build of the NF binary (and its workspace deps).
CARGO_INCREMENTAL=0 cargo build --release -p iwf-node
#  → target/release/iwf-node

# Tests + format (gate before shipping).
CARGO_INCREMENTAL=0 cargo test --workspace
cargo fmt --all -- --check

# Lint with the snap toolchain in a SEPARATE target dir (the 1.75 install has
# no clippy; mixing clippy-driver 1.95 against 1.75 rmeta fails with
# "invalid metadata"). The dir is ~3 GB and regenerable — delete it after.
PATH=/snap/bin:$PATH CARGO_TARGET_DIR=target-clippy CARGO_INCREMENTAL=0 \
  cargo clippy --workspace --all-targets
rm -rf target-clippy
```

Artifacts to ship:

```text
target/release/iwf-node          # the binary
config/config.yaml               # base config (edit per environment)
config/rules-nhss.yaml           # translation rules (or a rules.d/ directory)
config/dictionary.yaml           # AVP dictionary (or a dictionary.d/ directory)
```

---

## 2. ⚠️ The glibc rule — build *on the target's userland*

The binary is dynamically linked against the build host's **glibc**. A binary
built on a newer glibc will **not start** on an older host:

```text
build host : GLIBC 2.35   (Ubuntu 22.04)
Open5GS host: GLIBC 2.31  (Ubuntu 20.04)   →  binary copied across will fail
```

Choose one:

- **(A) Build on the target host** (recommended for bare metal). Install the
  1.75 toolchain there, copy the *source*, and run §1 on the host. This is what
  `deploy-open5gs.md` does.
- **(B) Build in a matching container.** Compile inside an image whose glibc
  is **≤** the target's (e.g. `ubuntu:20.04` for a 2.31 host), then ship the
  binary. A Kubernetes runtime image must likewise be ≤ the build glibc.
- **(C) Fully static** via `--target x86_64-unknown-linux-musl` if you add the
  musl target and your TLS/crypto deps build under musl (not the default
  path here).

Verify on the target before deploying further:

```bash
ldd --version | head -1                 # target glibc
./iwf-node --help 2>/dev/null || true   # must not print a GLIBC_x.y not found
```

---

## 3. Lay out the artifact on the remote server

```bash
# As root on the remote server:
install -d /opt/iwf /etc/iwf
install -m 0755 iwf-node                /opt/iwf/iwf-node
install -m 0644 config/rules-nhss.yaml  /etc/iwf/rules.yaml
install -m 0644 config/dictionary.yaml  /etc/iwf/dictionary.yaml
install -m 0644 config/config.yaml      /etc/iwf/config.yaml   # then edit, §4
```

Transfer from the build host (if not building on the target):

```bash
scp target/release/iwf-node user@server:/tmp/iwf-node
scp -r config            user@server:/tmp/iwf-config
# then `install ...` on the server as above
```

---

## 4. Configure

Edit `/etc/iwf/config.yaml` for the environment (full schema in
`config/config.yaml`). The fields that change per deployment:

```yaml
diameter:
  listen: "0.0.0.0:3868"               # Diameter (Cx/Sh/Rx/Ro/Rf) ingress
  origin_host: "iwf-0.epc.example.org" # MUST be this node's FQDN
  origin_realm: "epc.example.org"
sba:
  nrf_uri: "http://<nrf-host>:7777"    # the 5GC NRF
admin:
  listen: "0.0.0.0:8080"               # admin API (rules/dictionary/log-level)
  metrics_listen: "0.0.0.0:9090"       # Prometheus /metrics
  jwt_rs256_public_key: "/etc/iwf/admin-jwt/public.pem"   # prod: RS256
  # jwt_hs256_secret_env: "IWF_ADMIN_JWT_SECRET"          # lab: HS256 via env
rules_file: "/etc/iwf/rules.yaml"        # file OR /etc/iwf/rules.d directory
dictionary_file: "/etc/iwf/dictionary.yaml"
# notification: { listen: "0.0.0.0:8081", advertised_uri: "http://<this-host>:8081" }
```

**Runtime environment variables** (read by `iwf-node`):

| Var | Default | Purpose |
|---|---|---|
| `IWF_CONFIG` | `/etc/iwf/config.yaml` | config file path |
| `IWF_LOG_LEVEL` | `info` | initial log filter (EnvFilter directive — see [`logging.md`](logging.md)) |
| `IWF_SBA_HTTP1` | *(unset)* | unset ⇒ **HTTP/2 cleartext (h2c)** for real cores; set ⇒ HTTP/1.1 (only for HTTP/1.1 mocks) |
| `IWF_NRF_REQUESTER_NF_TYPE` | `IWF` | NRF discovery `requester-nf-type`; **Open5GS needs `AUSF`** |
| `IWF_OAUTH_CLIENT_ID` | *(unset)* | set ⇒ OAuth2 SBA tokens; unset ⇒ anonymous (lab mode) |
| `IWF_NF_INSTANCE_ID` | random UUID | stable NF instance id across restarts (optional) |
| *(JWT secret env)* | — | the env named by `admin.jwt_hs256_secret_env`, if using HS256 |

---

## 5. Run

**Foreground (smoke):**

```bash
IWF_CONFIG=/etc/iwf/config.yaml \
IWF_LOG_LEVEL=info \
IWF_NRF_REQUESTER_NF_TYPE=AUSF \
/opt/iwf/iwf-node
```

**As a systemd service** (`/etc/systemd/system/iwf.service`):

```ini
[Unit]
Description=IMS-5GC Interworking Function
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/iwf/iwf-node
Environment=IWF_CONFIG=/etc/iwf/config.yaml
Environment=IWF_LOG_LEVEL=info
Environment=IWF_NRF_REQUESTER_NF_TYPE=AUSF
# Environment=IWF_ADMIN_JWT_SECRET=...        # if HS256
Restart=on-failure
# Give SIGTERM time to drain in-flight transactions (match drain_timeout_s).
TimeoutStopSec=35
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now iwf
journalctl -u iwf -f          # structured JSON logs
```

Graceful shutdown: on `SIGTERM` the node flips readiness to *not ready*, drains
in-flight Diameter transactions up to `drain_timeout_s`, then deregisters from
the NRF and exits.

---

## 6. Verify the deployment

```bash
# Liveness / readiness (readyz is green once NRF-registered + a peer is OPEN).
curl -s http://<host>:8080/healthz        # 200
curl -s http://<host>:8080/readyz         # "ready" once registered + peer up

# Telemetry — confirms which 5GC service the IWF actually called.
curl -s http://<host>:9090/metrics | grep -E 'iwf_diameter_requests_total|iwf_sba_requests_total'

# In the logs you should see, at startup:
#   "IWF up", "registered with NRF", "nrf discovery refresh target_nf=..."
```

Drive a real Cx transaction and load-check with the bundled generator:

```bash
/opt/iwf/loadgen <host>:3868 --tps 1000 --connections 8 --seconds 30   # if shipped
```

For the full Open5GS bring-up (subscriber provisioning, the AF-registration
patch, h2c specifics) follow [`deploy-open5gs.md`](deploy-open5gs.md).

---

## 7. Upgrades & rollback

- **Rules / dictionary** change **without a restart**: `PUT /admin/v1/rules`
  and `PUT /admin/v1/dictionary` (validated; a bad document is rejected and the
  running set stays active). See [`logging.md`](logging.md) for calling the
  admin API.
- **Log verbosity** changes without a restart: `PUT /admin/v1/log-level`.
- **Binary** upgrade: blue/green or `systemctl restart iwf` (SIGTERM drains
  first). Keep the previous `/opt/iwf/iwf-node.<version>` for rollback.
