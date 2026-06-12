# ADR-0004: Stateless horizontally-scaled pods; no clustering layer

## Status
Accepted.

## Context
Five-nines and tens of millions of subscribers. Options: (a) stateless pods
where all durable subscriber state stays in UDM/UDR/HSS, (b) clustered IWF
with replicated session state (raft/gossip).

## Decision
Stateless. The IWF holds only *transaction-scoped* state (pending answer
correlation, NRF discovery cache, OAuth tokens) — all reconstructible in
milliseconds. Diameter sessions on Cx/Sh are stateless by 3GPP design
(`Auth-Session-State: NO_STATE_MAINTAINED`). A pod loss costs only its
in-flight transactions; IMS peers retransmit per their own timers.
Scale-out = HPA on request rate; multi-region = independent deployments per
region with NRF-scoped discovery, peers configured per region.

## Consequences / rejected alternatives
- *Replicated session state (rejected)*: pays consensus latency on the hot
  path to protect state that the protocol already tolerates losing.
- Implication: any future stateful feature (e.g. Sh subscriptions/PNR
  origination) must externalize its state (UDR or operator KV), not grow a
  clustering layer here.
