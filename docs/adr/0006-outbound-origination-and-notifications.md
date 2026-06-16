# ADR-0006: Outbound Diameter origination + declarative 5GC notifications

## Status
Accepted (Phase 2).

## Context
Phase 1 covered *terminating* flows: an IMS Diameter request arrives, the IWF
calls a 5GC NF over SBI, and answers. The other half of every IMS interface is
**network-initiated**: the HSS deregisters a user (Cx RTR) or pushes a profile
(Cx PPR); the HSS notifies of changed data the AS subscribed to (Sh PNR); the
PCF signals a policy event (Rx RAR/ASR); charging sessions span multiple
messages (Ro CCR Initial/Update/Terminate). These need three things the
server-only front-end lacked: to **originate** Diameter outbound, to **receive**
a 5GC notification, and to **hold session state** linking the two.

## Decision
Three small, generic subsystems — built once, shared by every interface — plus
two DSL extensions, so each interface stays configuration, not code (ADR-0003).

1. **Outbound origination** (`iwf-node/src/peer_registry.rs`): OPEN peers are
   registered by Origin-Host at CER time. Origination reuses the connection's
   existing writer queue and adds a Hop-by-Hop→waiter table so the reader loop
   (previously discarding answers) resolves the originated request's answer. No
   second socket, no second writer.

2. **Notification callback server** (`iwf-node/src/notification.rs`): a
   dedicated listener (separate from the JWT-protected admin port). A 5GC NF
   `POST`s to the `callbackReference`/`notifyUri` the IWF advertised; the
   handler resolves the binding, builds the originated request declaratively,
   originates it, and maps the Diameter answer back (`204` on 2001). Peer
   offline → drop the binding and tell the NF (`410`).

3. **Binding store** (`iwf_core::ports::BindingStore`): one in-memory map keyed
   by Diameter Session-Id holds the peer to push back to and the 5GC resource
   handle. Serves Sh subscriptions, Rx app-sessions and Ro charging refs alike.
   In-memory (peer re-establishes on restart); the port allows persistence.

4. **DSL: reverse translation + stateful hooks.** A `notifications:` section
   maps notification JSON → an originated request, reusing the Phase-1
   `AvpSpec`/`AvpSource` machinery verbatim (`from_json`, `from_body`, `concat`,
   `group`); a `match` selects among events sharing a kind (RTR vs PPR, RAR vs
   ASR), and `reuse_session` shares the forward session (Rx). Forward rules gain
   `bind` / `bind_lookup` / `unbind` actions (with an optional `when` guard for
   the Ro CCR Initial/Update/Terminate fork) and a `{notification_uri}` built-in.

## Consequences / rejected alternatives
- *Hardcode each originated message in Rust (rejected)*: fast to write but
  re-introduces the per-interface recompile ADR-0003 removed; the declarative
  path covers PNR/RTR/PPR/RAR/ASR with zero compiled builders.
- *Fold the callback onto the admin port (rejected)*: mixes an unauthenticated
  NF-facing surface with the operator API. Separate listener instead.
- *Persistent binding store now (deferred)*: in-memory is correct (peers
  re-subscribe on restart); the port leaves the upgrade path open.
- The `when` guard is deliberately minimal (var == value); it is the only
  branching the action list has, justified by the Ro CCR family. Anything
  richer would head back toward the embedded-scripting option ADR-0003 rejected.
