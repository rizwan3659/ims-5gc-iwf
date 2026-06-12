# IWF Operational Runbook

## Startup
1. Pod starts; config loaded from `/etc/iwf/config.yaml` (ConfigMap),
   rules from `/etc/iwf/rules.yaml`.
2. Required env: `IWF_OAUTH_CLIENT_ID`/`IWF_OAUTH_CLIENT_SECRET` (Secret),
   optionally `IWF_NF_INSTANCE_ID`, `IWF_LOG_LEVEL`.
3. Node registers with NRF (retries with backoff — pod stays NotReady until
   success), starts Diameter listener (3868), admin (8080), metrics (9090).
4. Verify: `kubectl exec ... -- wget -qO- localhost:8080/readyz` → `ready`;
   `iwf_peer_state{state="r_open"} 1` once peers connect.

## Shutdown / upgrade (zero-downtime)
- Rolling update relies on the SIGTERM sequence: readiness false → drain
  in-flight (≤ `drain_timeout_s`) → DPR to peers → NRF deregister → exit.
- `terminationGracePeriodSeconds` must exceed `drain_timeout_s` + 10 s.
- PDB `minAvailable: 2` + `maxUnavailable: 1` rolling keeps capacity.
- Verify after each pod: achieved TPS flat, `iwf_diameter_requests_total`
  error-code share unchanged.

## Peer management
- Peers connect inbound; CER from an unknown realm/application is answered
  3007 and closed — check `applications` advertised vs Cx/Sh.
- Peer flapping: look at `iwf_peer_state` transitions + logs
  `"peer idle past watchdog budget"` (network) vs `"FSM violation"` (peer bug).
- To drain one peer: scale a new pod set first, then firewall the peer at
  the LB; in-flight to that peer fails over per session table.

## Certificate rotation
- Certs are Secret volume mounts. Update the Secret; kubelet syncs the
  mount; the inotify watcher reloads (`"server TLS certificate reloaded"`).
- A bad rotation logs an error and keeps serving the old cert — alert on
  `log_level=ERROR message~"tls"`; fix the Secret, no restart needed.

## Rules management
- `GET /admin/v1/rules` (read role) to inspect; `PUT /admin/v1/rules`
  (provisioning role) to replace. 422 = rejected, old rules still live.
- Staged rollout: push two rules with the same trigger and split
  `rollout_percent`; bucketing is sticky per end-to-end id.

## Scaling
- HPA scales on Diameter request rate; manual: `kubectl scale deploy/iwf`.
- Sizing baseline: 4-core pod ≥25k TPS (validate per release, below).
- NUMA: on multi-socket workers, pin pods to one socket via
  `topologyManager` (single-numa-node policy) + CPU Manager static policy;
  the runtime sizes workers to the cgroup quota automatically.

## Benchmarking / TPS acceptance
- `cargo run --release -p iwf-benchmark --bin loadgen -- <iwf>:3868
  --tps 25000 --connections 16 --seconds 300` per generator; run 4
  generators against a 4–6 pod deployment for the 100k acceptance.
- Pass: achieved ≥ target, loadgen p99 < 20 ms, unanswered < 0.1%,
  `iwf_diameter_latency_seconds` p99 (internal) < 5 ms.
- Criterion micro-benches: `cargo bench -p iwf-benchmark` (codec regression
  gate in CI).

## Soak / leak validation
- 72 h at 50% target TPS; watch container RSS (flat after warmup),
  `iwf_active_sessions_total` (sawtooth, no ramp), fd count.
- Heap profiling build: rerun with jemalloc/heaptrack image variant
  (profiling feature hooks are documented in iwf-benchmark; flamegraphs via
  `cargo flamegraph -p iwf-node`).

## Incident response quick table
| Symptom | First checks | Likely cause / action |
|---|---|---|
| 3004 spike | `iwf_active_sessions_total` vs `max_in_flight`; CPU | overload → scale out; or NF latency backing up the pipe |
| 3002/5012 spike | breaker states in logs; NRF reachability; target NF health | NF outage → confirm failover took <500 ms; engage NF owner |
| UAA 5001 spike | which rule (`iwf_translation_errors_total`), UDM 404 rate | provisioning gap (subscribers missing in UDM), not an IWF fault |
| p99 latency up | `iwf_sba_latency_seconds` vs `iwf_diameter_latency_seconds` | SBA-side slow → NF/network; both slow → CPU throttling, check limits |
| readiness flapping | heartbeat logs; NRF availability | NRF instability; cached discovery keeps data plane alive |
| peer down alarm | `iwf_peer_state`, TCP to peer, watchdog logs | network or peer restart; FSM reconnects; check IMS-side LB |
