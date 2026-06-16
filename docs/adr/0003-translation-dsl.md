# ADR-0003: YAML rule DSL + trait-object plugins for translation

## Status
Accepted.

## Context
Mapping tables between Diameter commands and SBI operations change per
operator, per 3GPP release, and during migrations (A/B). A hardcoded match
table would force a rebuild/redeploy for every mapping change.

## Decision
Declarative rules (YAML/TOML): trigger (application + command), ordered
actions (`extract`, `set_var`, `http_request`, `map_response`), version
label and `rollout_percent` for staged rollouts (sticky bucketing on
End-to-End id).
Validation happens at load time (unknown AVP names, duplicate ids, missing
`map_response` all fail the *reload*, never a live call). The document is
held in an `ArcSwap` — readers pay one atomic load; activation is atomic;
a bad document can never become active.

Two further layers keep interfaces configuration-only:

- **Runtime AVP catalog** (`AvpCatalog`): rule AVP names resolve through a
  YAML dictionary (`dictionary_file`, organized per interface — base/cx/sh)
  giving each AVP its code, vendor and Diameter type. The type drives both
  `extract` (integer AVPs render as decimal strings for `set_var` tables)
  and answer encoding. Without a dictionary the builtin Cx/Sh table applies.
- **Inline answer specs**: a `map_response` value is either a plugin name or
  a declarative build — `result_code` / `experimental_result` plus ordered
  AVPs sourced `value` (with `{var}` substitution), `from_json` (RFC 6901
  pointer), `from_body`, `concat` (+ `decode: hex`, e.g. RAND‖AUTN) or
  nested `group`. Adding an interface or NF service (e.g. Nhss in
  `config/rules-nhss.yaml`) therefore needs no Rust at all.

Logic beyond the DSL (computed mappings, e.g. TBCD) still lives in
`TranslationPlugin` trait objects resolved by name from `map_response`;
operators register custom plugins without touching the engine.

## Consequences / rejected alternatives
- *Hardcoded switch (rejected)*: fastest, but couples operator config to
  release trains.
- *Embedded scripting — Lua/WASM (rejected for now)*: maximum flexibility,
  but unbounded execution time inside a 5 ms budget and a much larger
  security/audit surface. The plugin trait covers the same need in safe Rust.
