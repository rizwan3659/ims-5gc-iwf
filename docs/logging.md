# Logging & telemetry

The IWF emits **structured JSON logs** via `tracing`, with a **hot-reloadable
per-target filter** (no restart), end-to-end **correlation ids**, and a strict
**PII policy**. Metrics and tracing are covered at the end.

Implementation: `iwf-observability` (`logging.rs`, `metrics.rs`); the runtime
filter is wired to the admin API in `iwf-admin`.

---

## 1. Log format

One JSON object per event:

```json
{
  "timestamp": "2026-06-17T05:38:52.914979Z",
  "level": "INFO",
  "fields": { "message": "nrf discovery refresh", "target_nf": "HSS", "instances": 1 },
  "target": "iwf_discovery::cache",
  "span": { "name": "diameter_transaction", "correlation_id": "bf66de8d-…",
            "interface": "cx", "command": "UAR" }
}
```

- `target` — the emitting module path (used as the **filter key**, §2).
- `fields.message` + structured fields — the event payload.
- `span` — the active span. For request processing this is
  `diameter_transaction`, which carries the **`correlation_id`**, `interface`
  and `command`. Events emitted while handling a request inherit these.

> Correlation appears under **`span.correlation_id`** (the formatter attaches
> the current span, not a flattened top-level field). Query/aggregate on
> `span.correlation_id`.

---

## 2. Levels & filters (EnvFilter)

The filter is an **`EnvFilter`** directive string — far more than a single
global level. Grammar (comma-separated):

```text
<level>                         global level         e.g.  debug
<target>=<level>                per-module           e.g.  iwf_diameter=trace
<target::submodule>=<level>     per-submodule        e.g.  iwf_diameter::transport=warn
```

Levels: `trace | debug | info | warn | error | off`.
Targets are the crate/module names: `iwf_node`, `iwf_diameter`,
`iwf_translation`, `iwf_sba`, `iwf_discovery`, `iwf_admin`, `iwf_security`,
`iwf_config`, `iwf_observability`, `iwf_core`.

### Initial filter (startup)

Set via `IWF_LOG_LEVEL` (default `info`); it accepts a full directive string,
so per-module filtering works from boot:

```bash
IWF_LOG_LEVEL=info,iwf_diameter::transport=warn,iwf_sba=debug /opt/iwf/iwf-node
```

An unparseable value falls back to `info`.

---

## 3. Runtime hot-reload (no restart)

`PUT /admin/v1/log-level` on the admin listener swaps the active filter
atomically. Body = the new directive string. Requires the **`operate`**
permission (a JWT with an operator scope); a malformed directive is rejected
and the previous filter stays active.

```bash
TOKEN=<operator JWT>
ADMIN=http://<host>:8080/admin/v1/log-level

# Global INFO → DEBUG
curl -X PUT -H "Authorization: Bearer $TOKEN" --data 'debug' "$ADMIN"            # 204

# TRACE one module (the Diameter codec)
curl -X PUT -H "Authorization: Bearer $TOKEN" --data 'info,iwf_diameter=trace' "$ADMIN"

# Detail specific NF adapters (the SBI/translation side)
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  --data 'info,iwf_sba=debug,iwf_discovery=debug' "$ADMIN"

# Disable a noisy protocol target without touching the rest
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  --data 'info,iwf_diameter::transport=warn' "$ADMIN"

# Malformed → 400 (filter unchanged); no/invalid token → 401/403
curl -X PUT -H "Authorization: Bearer $TOKEN" --data 'iwf_diameter=bogus' "$ADMIN"   # 400
```

Each successful change is itself logged: `"log filter changed"` with the new
`filter`. Revert by PUT-ing the baseline (e.g. `info`).

---

## 4. Correlation — tracing a subscriber transaction end-to-end

- A **UUID `correlation_id`** is generated at Diameter ingress
  (`iwf_observability::correlation_id()`) and attached to the
  `diameter_transaction` span, so every log line for that transaction carries
  it under `span.correlation_id`.
- It is propagated **downstream to the 5GC**: every SBA/HTTP call sets the
  request header **`x-correlation-id`** (and the internal `SbiRequest`
  carries it), so the Diameter request and the Nhss/Npcf/Nchf calls it
  triggers are linkable across the IWF and into the core.

To follow one transaction, filter your log store on
`span.correlation_id == "<uuid>"`; to trace one *while it happens*, raise the
level (§3) and grep `journalctl -u iwf` for the id.

---

## 5. PII policy

Subscriber identities (**IMPI / IMPU / SUPI / MSISDN**) are **never written to
logs** in standard builds — error messages carry a class + reason, not the raw
value (e.g. `invalid IMPI: bad realm`, never the IMPI itself). Cleartext
identity logging is gated behind the `pii-logging` build feature and must not
be enabled in production. Keep this in mind when raising levels to `trace`:
protocol/codec traces stay PII-clean by design.

---

## 6. Telemetry: metrics & tracing

**Prometheus metrics** on the metrics listener (`/metrics`, default `:9090`):

| Metric | Use |
|---|---|
| `iwf_diameter_requests_total{interface,command,result_code}` | Diameter throughput & outcomes |
| `iwf_diameter_latency_seconds` | per-transaction latency histogram |
| `iwf_sba_requests_total{nf_type,operation,http_status}` | the **translated** 5GC calls |
| `iwf_sba_latency_seconds` | SBA call latency |
| `iwf_translation_errors_total{rule_id,error_type}` | translation failures |
| `iwf_nrf_discovery_latency_seconds`, `iwf_peer_state`, `iwf_active_sessions_total` | discovery / peer / load |

```bash
curl -s http://<host>:9090/metrics | grep '^iwf_'
```

**Distributed tracing:** the span structure (one `diameter_transaction` span
per request, a child span per SBA call, correlation propagated) is in place via
`tracing`. **OTLP/OpenTelemetry export is feature-gated behind `otlp` and off
by default** (the OTLP crates need a newer rustc than the pinned 1.75); in the
default build, spans surface in the JSON logs (§1) rather than an external
trace backend.

---

## 7. Quick recipes

| Goal | Filter to PUT (or `IWF_LOG_LEVEL`) |
|---|---|
| Everything at DEBUG | `debug` |
| Trace Diameter codec/AVP parsing | `info,iwf_diameter=trace` |
| Debug the 5GC-facing side (discovery + SBA calls) | `info,iwf_sba=debug,iwf_discovery=debug` |
| Debug rule/translation decisions | `info,iwf_translation=debug` |
| Silence watchdog/transport chatter | `info,iwf_diameter::transport=warn` |
| Back to baseline | `info` |
