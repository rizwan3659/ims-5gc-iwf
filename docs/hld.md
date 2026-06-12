# IWF High-Level Design

## 1. Component view

```
                IMS side (Diameter)                 5GC side (SBA / HTTP2)
  ┌──────┐  Cx/Dx   ┌────────────────────────────────────────┐   Nudm   ┌─────┐
  │I-CSCF│◄────────►│                IWF pod                 │◄────────►│ UDM │
  └──────┘          │ ┌────────────┐  ┌───────────────────┐  │   Nausf  ├─────┤
  ┌──────┐  Cx      │ │ iwf-diameter│  │  iwf-translation │  │◄────────►│AUSF │
  │S-CSCF│◄────────►│ │ codec/FSM/  │─►│  rule engine +   │  │   Namf   ├─────┤
  └──────┘          │ │ routing/    │  │  plugins         │  │◄────────►│ AMF │
  ┌──────┐  Sh      │ │ sessions    │◄─│  (ArcSwap rules) │  │   Nudr   ├─────┤
  │ AS   │◄────────►│ └────────────┘  └───────┬───────────┘  │◄────────►│ UDR │
  └──────┘          │        ▲                │ SbaPort      │          └─────┘
                    │        │         ┌──────▼─────┐        │   Nnrf   ┌─────┐
                    │  metrics/logs    │  iwf-sba   │        │◄────────►│ NRF │
                    │ (observability)  │ pool/retry/│        │ reg+disc └─────┘
                    │        ▲         │ breaker    │        │
                    │ ┌──────┴──────┐  └──────┬─────┘        │
                    │ │  iwf-admin  │  ┌──────▼─────────┐    │
                    │ │ health/RBAC │  │ iwf-discovery  │    │
                    │ └─────────────┘  │ cache/heartbeat│    │
                    │                  └────────────────┘    │
                    └────────────────────────────────────────┘
         iwf-core: domain types + ports (no I/O) — everything depends inward.
         iwf-security: TLS1.3/mTLS, OAuth2 cache, JWT, RBAC (cross-cutting).
         iwf-config: validated hot-reload snapshots (watch channel).
```

## 2. Transaction data flow (Cx UAR, happy path)

1. Frame read (1 allocation) → zero-copy decode → FSM check (peer OPEN).
2. Ingress gate: in-flight count vs `max_in_flight` → else 3004 shed.
3. Rule select (atomic load + match on app/command + A/B bucket).
4. `extract` actions slice AVPs; `http_request` builds `SbiRequest`.
5. SBA client: resolve endpoints (TTL cache, usually no NRF hit) → bearer
   token (cached, 80% TTL refresh) → breaker admit → pooled HTTP/2 exchange.
6. `map_response` selects builder by status → answer built (1 allocation),
   queued on the bounded writer channel → framed write + flush.
7. Metrics: diameter counter+histogram, sba counter+histogram; logs carry
   the correlation id; transaction span ends.

Budget: steps 1–4,6–7 are the <5 ms internal budget (micro-benchmarked
codec ≪1 µs; rule match is a vector scan over ~10 rules); step 5 is the
end-to-end 20 ms budget consumer.

## 3. Failure mode analysis

| Failure | Detection | Response | Blast radius |
|---|---|---|---|
| NF endpoint down | connect/timeout errors | breaker trips after 5 consecutive; resolver marks unhealthy + TTL drop; retry lands on next endpoint same attempt loop (<500 ms) | one endpoint until NRF refresh |
| All endpoints of an NF down | breaker open on all | requests answered 3002/5012 per rules; readiness stays up (IMS may still use other flows) | one NF type's flows |
| NRF down | discovery/heartbeat errors | serve cached endpoints until TTL ceiling; heartbeat backs off exponentially; readiness degrades when registration lapses | discovery refresh only |
| Diameter peer dies silently | RFC 3539 watchdog (2 missed DWAs) | connection closed, peer-routed pending transactions failed over, gauge flips, reconnect timer | one peer's transactions |
| Ingress overload | in-flight ≥ threshold | immediate 3004 (shed at ingress, no queueing) | excess load only |
| Bad rule push | load-time validation | reload rejected (422), previous rules stay active | none |
| Bad cert rotation | reload error | previous TLS config stays active; alert via log/metric | none |
| Pod kill / upgrade | SIGTERM | readiness false → drain in-flight (≤30 s) → DPR peers → NRF deregister → exit | in-flight only, bounded |
| Region loss | external LB health | DNS/anycast away; peer regions independent (ADR-0004) | one region |

## 4. Scaling model

Stateless pods (ADR-0004). HPA on `iwf_diameter_requests_total` rate.
Sizing basis: a 4-core pod sustains ≥25k TPS with p99 headroom (codec ≪1 µs,
hot path allocation-bounded); 100k TPS ⇒ 4–6 pods plus N+2 for zone loss
and upgrade surge. Validate per-release with `iwf-benchmark` (see runbook).
