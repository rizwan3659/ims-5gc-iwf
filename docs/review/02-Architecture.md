# 2. Architecture (HLD + LLD) — Mermaid

Companion to `docs/hld.md` (prose + failure-mode table) and `docs/lld.md`
(per-crate structure + lock inventory). This document adds the requested
Mermaid diagrams.

## 2.1 Architectural style

- **Hexagonal (ports & adapters)**: `iwf-core` holds domain types + ports
  (`SbaPort`, `EndpointResolver`, `TokenProvider`); adapters live in
  `iwf-sba`, `iwf-discovery`, `iwf-security`. Composition happens only in
  `iwf-node`.
- **Stateless service** (ADR-0004) for horizontal scale.
- **Configuration-driven behaviour** (ADR-0003): translation is data, not code.
- **Pure-core concurrency**: the peer FSM is a pure transition function;
  shared state uses `DashMap`/atomics/`ArcSwap` (lock inventory in `lld.md`).

## 2.2 Component diagram

```mermaid
graph TB
  subgraph IMS["IMS (Diameter)"]
    ICSCF[I/S-CSCF]
    AS[Application Server]
  end

  subgraph POD["IWF pod (iwf-node)"]
    direction TB
    DF["Diameter front-end<br/>(listener, peer FSM,<br/>ingress shed, drain)"]
    TR["iwf-translation<br/>(rule engine + plugins,<br/>ArcSwap ruleset)"]
    SBA["iwf-sba<br/>(HTTP/2 pool, breaker, retry)"]
    DISC["iwf-discovery<br/>(NRF reg/heartbeat,<br/>TTL endpoint cache)"]
    SEC["iwf-security<br/>(TLS, OAuth cache, JWT, RBAC)"]
    OBS["iwf-observability<br/>(metrics, logs)"]
    ADM["iwf-admin<br/>(health, rules, log-level)"]
    CFG["iwf-config<br/>(validated hot-reload)"]
  end

  subgraph FIVEGC["5G Core (SBA / HTTP2)"]
    NRF[NRF]
    UDM[UDM]
    UDR[UDR]
    AUSF[AUSF]
    AMF[AMF]
  end

  ICSCF -- "Cx/Dx Diameter" --> DF
  AS -- "Sh Diameter" --> DF
  DF --> TR
  TR -- "SbaPort" --> SBA
  SBA -- "resolve()" --> DISC
  SBA -- "bearer_token()" --> SEC
  SBA -- "Nudm/Nausf/Namf/Nudr (h2c)" --> UDM & UDR & AUSF & AMF
  DISC -- "register/heartbeat/discover" --> NRF
  ADM -. "RBAC" .- SEC
  DF & SBA & DISC --> OBS
  CFG -. "snapshots" .- DF & SBA
```

## 2.3 Request flow — Cx UAR (verified path)

```mermaid
sequenceDiagram
    autonumber
    participant P as IMS peer (I-CSCF)
    participant DF as Diameter front-end
    participant EN as Translation engine
    participant DI as Discovery (NRF cache)
    participant SE as Token cache
    participant UDM as Open5GS UDM

    P->>DF: CER
    DF-->>P: CEA (2001)
    P->>DF: UAR (User-Name, Public-Identity)
    DF->>DF: ingress gate (in-flight < max?)
    DF->>EN: translate(UAR, correlation_id)
    EN->>EN: select rule (app 16777216, cmd 300)
    EN->>EN: extract AVPs -> vars
    EN->>DI: resolve(UDM)
    DI-->>EN: endpoint (cache hit, no NRF call)
    EN->>SE: bearer_token(UDM)
    SE-->>EN: token (cached)
    EN->>UDM: GET /nudm-sdm/v2/{supi}/am-data (h2c)
    UDM-->>EN: 200 + subscription JSON
    EN->>EN: map_response 200 -> build_uaa_success
    EN-->>DF: UAA (Result-Code 2001)
    DF-->>P: UAA
    Note over DF,UDM: metrics + correlation-id logged throughout
```

## 2.4 Data flow

```mermaid
flowchart LR
  A["Diameter frame<br/>(bytes::Bytes, 1 alloc)"] --> B["zero-copy AVP decode<br/>(slices into frame)"]
  B --> C["extract: AVP -> vars<br/>(IMPI, IMPU)"]
  C --> D["template subst<br/>path/query/body"]
  D --> E["SbiRequest"]
  E --> F["HTTP/2 to NF"]
  F --> G["SbiResponse (JSON)"]
  G --> H["plugin builds answer<br/>(AVP groups)"]
  H --> I["Diameter answer<br/>(1 alloc) -> wire"]
```

## 2.5 Peer FSM state machine (RFC 6733 §5.6 + RFC 3539)

```mermaid
stateDiagram-v2
    [*] --> Closed
    Closed --> WaitConnAck: Start / Connect
    Closed --> ROpen: R-Rcv-CER / SendCEA
    WaitConnAck --> WaitICea: I-Rcv-Conn-Ack / SendCER
    WaitConnAck --> Closed: I-Rcv-Conn-Nack / ArmReconnect
    WaitICea --> IOpen: I-Rcv-CEA / ArmWatchdog
    WaitICea --> Closed: I-Rcv-CEA-Failed
    IOpen --> IOpen: Rcv-DWR / SendDWA
    ROpen --> ROpen: Rcv-DWR / SendDWA
    IOpen --> Closed: 2x Tw-Expired / Failover
    ROpen --> Closed: 2x Tw-Expired / Failover
    IOpen --> Closing: Stop / SendDPR
    ROpen --> Closing: Stop / SendDPR
    Closing --> Closed: Rcv-DPA / Disconnect
    IOpen --> Closed: Rcv-DPR / SendDPA+Failover
    note right of Closed
      Collision/election (§5.6.4) handled via
      WaitConnAckElect / WaitReturns (see peer.rs)
    end note
```

## 2.6 Deployment architecture

```mermaid
graph TB
  subgraph REGION["Region (multi-AZ)"]
    LB[Diameter LB / IMS signalling]
    subgraph K8S["Kubernetes namespace ims-interworking"]
      HPA[HPA on req-rate]
      PDB["PDB minAvailable=2"]
      subgraph PODS["Deployment (anti-affinity per zone)"]
        P1[iwf pod z1]
        P2[iwf pod z2]
        P3[iwf pod z3]
      end
      NP[NetworkPolicy 3868/8080/9090]
      CM[ConfigMap config+rules]
      SEC[Secret tls/oauth/jwt]
    end
    subgraph CORE["5G Core"]
      NRFc[NRF]
      NFc[UDM/UDR/AUSF/AMF]
    end
  end
  LB --> P1 & P2 & P3
  P1 & P2 & P3 --> NRFc
  P1 & P2 & P3 --> NFc
  CM -.-> PODS
  SEC -.-> PODS
  HPA -.-> PODS
```

Runtime install (bare-metal/VM, FHS layout — `deploy/cdot/`):
```
/opt/CDOT-iwf/{bin,etc,lib,log,run}
  bin/cdot_iwf (start|stop|restart|status), iwf-node, loadgen, tests.sh
```

## 2.7 External dependencies & third-party integrations

| Integration | Direction | Protocol | Notes |
|---|---|---|---|
| IMS peers (I/S-CSCF, AS) | inbound | Diameter/TCP 3868 | terminates Cx/Sh |
| NRF | out | HTTP/2 (h2c) Nnrf | register/heartbeat/discover |
| UDM/UDR/AUSF/AMF | out | HTTP/2 (h2c) | per translation rules |
| OAuth2 AS (often NRF) | out | HTTP/2 | client-credentials tokens |
| Prometheus | inbound scrape | HTTP `:9090` | metrics |
| Admin clients | inbound | HTTP `:8080` + JWT | rules/log-level |
| Service mesh (Istio) | sidecar | mTLS | optional transport security overlay |

## 2.8 Security boundaries

```mermaid
graph LR
  subgraph TRUST["IWF trust zone"]
    NODE[iwf-node]
  end
  IMS[IMS signalling net] -->|"NetworkPolicy 3868"| NODE
  OPS[Ops namespace] -->|"NetworkPolicy 8080 + JWT/RBAC"| NODE
  MON[Monitoring] -->|"NetworkPolicy 9090"| NODE
  NODE -->|"OAuth2 bearer + (mesh mTLS)"| FIVEGC[5G Core SBI]
  SECRETS[(K8s Secret / Vault)] -.->|"env injection"| NODE
```

Boundaries: (a) Diameter ingress (network-restricted; no app auth — Diameter
peers are trusted by realm/CER), (b) admin ingress (JWT + RBAC), (c) SBI
egress (OAuth2 + intended mTLS), (d) secrets (never in config files; env /
Secret only).

## 2.9 Cross-cutting strategies (summary; detail in `docs/hld.md`)

- **Config**: `iwf-config` deny-unknown-fields schema, semantic validation,
  inotify hot-reload publishing `Arc<Config>` snapshots.
- **Logging/monitoring**: `tracing` JSON, runtime level via admin API,
  correlation id per transaction, Prometheus families per
  `iwf-observability::metrics`.
- **Scalability**: stateless pods + HPA on `iwf_diameter_requests_total` rate.
- **Reliability**: peer watchdog/failover, circuit breaker, in-transaction
  endpoint failover (<500 ms), validated hot-reload, graceful drain.
- **Performance**: zero-copy codec (≈2 allocs/transaction), HTTP/2
  multiplexed pool, SLO-shaped histograms.

## 2.10 Assumptions & constraints

- Build toolchain pinned for rustc 1.75 (ADR-0005); exact dependency pins.
- 5GC SBI is HTTP/2 cleartext inside the mesh; mTLS mesh-provided today.
- NRF authorizes discovery by requester NF type (deployment-configurable).
- Subscriber data lives in the 5G core (UDM/UDR); the IWF stores none.
