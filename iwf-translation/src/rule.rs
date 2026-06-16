//! Translation rule DSL: schema, parsing (YAML and TOML), validation, and
//! the hot-swappable [`RuleStore`].
//!
//! Schema (YAML form):
//!
//! ```yaml
//! rules:
//!   - id: cx_uar_to_udm_identity_query
//!     trigger:
//!       diameter_application: 16777216   # Cx
//!       command_code: 300                # UAR
//!     actions:
//!       - extract: { avp: "User-Name", as: impi }
//!       - extract: { avp: "Public-Identity", as: impu }
//!       - http_request:
//!           method: GET
//!           nf_type: UDM
//!           path: "/nudm-uecm/v1/{impi}/registrations"
//!           query:
//!             impu: "{impu}"
//!       - map_response:
//!           200: build_uaa_success
//!           404: build_uaa_user_unknown
//!           503: build_uaa_unable_to_comply
//!     version: "3gpp-rel18"
//!     rollout_percent: 100   # optional, default 100 (A/B staged rollout)
//! ```
//!
//! `map_response` values are either the **name of a compiled plugin** (as
//! above — the escape hatch for computed mappings) or an **inline answer
//! spec** that the engine renders declaratively, so a new interface or NF
//! service needs no Rust at all:
//!
//! ```yaml
//!       - map_response:
//!           200:
//!             result_code: 2001
//!             avps:
//!               - { avp: Server-Name, from_json: "/serverName" }
//!               - { avp: User-Data, from_body: true }
//!               - avp: SIP-Auth-Data-Item
//!                 group:
//!                   - { avp: SIP-Authentication-Scheme, value: "Digest-AKAv1-MD5" }
//!                   - avp: SIP-Authenticate
//!                     required: true
//!                     concat:
//!                       - { from_json: "/av5gAka/rand", decode: hex }
//!                       - { from_json: "/av5gAka/autn", decode: hex }
//!           404: { experimental_result: 5001 }
//!           default: { result_code: 5012 }
//! ```
//!
//! AVP names resolve through the runtime [`crate::catalog::AvpCatalog`]
//! (dictionary file or builtin), whose `type` drives the value encoding.

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use iwf_core::error::CoreError;
use iwf_core::nf::NfType;
use iwf_core::ports::SbiMethod;
use serde::Deserialize;

use crate::catalog::{AvpCatalog, AvpKind, CatalogStore};

/// Trigger: which Diameter requests a rule applies to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trigger {
    /// Diameter Application-Id (e.g. 16777216 for Cx).
    pub diameter_application: u32,
    /// Command-Code (e.g. 300 for UAR).
    pub command_code: u32,
}

/// One step of a rule. The document form is a single-key mapping per step:
/// `- extract: {...}` / `- http_request: {...}` / `- map_response: {...}`
/// (deserialized through [`ActionMap`] because serde_yaml 0.9 reserves
/// external enum tagging for `!tag` notation).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "ActionMap")]
pub enum Action {
    /// Pull an AVP value into a named variable.
    Extract {
        /// AVP name (resolved via the [`AvpCatalog`]).
        avp: String,
        /// Variable name for later `{var}` substitution.
        var: String,
        /// When false, a missing AVP is allowed and the variable is unset.
        required: bool,
    },
    /// Issue one SBI request to a 5GC NF.
    HttpRequest {
        /// HTTP method (GET/POST/PUT/PATCH/DELETE).
        method: SbiMethod,
        /// Target NF type; endpoint selection happens in `iwf-discovery`.
        nf_type: NfType,
        /// Path template; `{var}` placeholders are substituted.
        path: String,
        /// Query parameters; values may contain `{var}` placeholders.
        query: BTreeMap<String, String>,
        /// Optional JSON body template (object with `{var}` placeholders in
        /// string values).
        body: Option<serde_json::Value>,
    },
    /// Derive a new variable by mapping the value of an existing variable
    /// through a lookup table. Enables conditional routing without a full
    /// branching language — e.g. SAR's `Server-Assignment-Type` → Nhss UECM
    /// operation, or Sh `Data-Reference` → SDM_Get resource segment
    /// (TS 29.562 §6 mappings). The mapped variable is then usable in
    /// `{var}` templates.
    SetVar {
        /// Source variable name (typically a prior `extract`).
        from: String,
        /// Destination variable name.
        var: String,
        /// Value → value lookup table (keys are the source value as string).
        /// An **empty** map means passthrough: the destination takes the
        /// source value verbatim (or `default` if the source is unset).
        map: BTreeMap<String, String>,
        /// Fallback when the source value is absent or (with a non-empty map)
        /// unmapped.
        default: Option<String>,
    },
    /// Record a [`iwf_core::ports::Binding`] keyed by the request's
    /// Session-Id, so a later server-push (PNR/RAR/ASR via the
    /// `notifications:` rules) can route back to this peer, or a teardown
    /// (`unbind`) can address the 5GC resource. Placed *after* the create
    /// `http_request` so `resource_*` can read its response.
    Bind {
        /// Binding family (`sh`/`rx`/`ro`); also selects the notification rule.
        kind: String,
        /// Subscriber identity template (`{var}`), stored for the push request.
        identity: String,
        /// JSON pointer into the last response for the 5GC resource handle
        /// (Npcf appSessionId, Nchf charging ref). Mutually exclusive with
        /// `resource_value`.
        resource_json: Option<String>,
        /// Resource handle as a `{var}` template (alternative to
        /// `resource_json`).
        resource_value: Option<String>,
        /// Run only when this guard holds (e.g. Ro: bind only on
        /// CC-Request-Type INITIAL). Unset → always.
        when: Option<Guard>,
    },
    /// Load the binding for the request's Session-Id into variables *without*
    /// removing it (Ro CCR-Update needs the chargingDataRef but the session
    /// lives on). Placed *before* the `http_request` that uses it.
    BindLookup {
        /// Variable to receive the binding's `resource_ref`.
        resource_as: String,
        /// Run only when this guard holds. Unset → always.
        when: Option<Guard>,
    },
    /// Remove the binding for the request's Session-Id (session teardown:
    /// STR, Ro Terminate) and optionally inject its stored `resource_ref`
    /// into a variable so the teardown `http_request` can address the 5GC
    /// resource. Placed *before* that `http_request`.
    Unbind {
        /// Variable to receive the binding's `resource_ref` (e.g. the
        /// appSessionId for the delete path). Unset → resource not needed.
        resource_as: Option<String>,
        /// Run only when this guard holds (e.g. Ro: unbind only on
        /// CC-Request-Type TERMINATION). Unset → always.
        when: Option<Guard>,
    },
    /// Map the most recent HTTP status to an answer: either a named builder
    /// (a [`crate::plugin::TranslationPlugin`] registered under that name)
    /// or an inline declarative [`AnswerBuild`]. The key `"default"`
    /// handles unlisted statuses.
    MapResponse(BTreeMap<String, AnswerSpec>),
}

/// A `notifications:` entry — how to turn an inbound 5GC notification into an
/// **originated** Diameter request (PNR/RTR/PPR/RAR/ASR). Selected by the
/// triggering [`iwf_core::ports::Binding`]'s `kind`. The `emit.avps` reuse the
/// same [`AvpSpec`] machinery as answers, so the reverse direction is
/// configuration too.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRule {
    /// Unique id (diagnostics).
    pub id: String,
    /// Binding family this rule serves (`sh`/`rx`/`ro`).
    pub bind_kind: String,
    /// Optional event discriminator: when several rules share a `bind_kind`
    /// (e.g. Cx RTR-deregistration vs PPR-profile-update, Rx RAR vs ASR), the
    /// notification body field selects which one to emit. Absent → matches any
    /// notification of this kind (use as the fallback, listed last).
    #[serde(rename = "match", default)]
    pub matcher: Option<NotificationMatch>,
    /// The request to emit.
    pub emit: EmitSpec,
}

impl NotificationRule {
    /// Whether this rule applies to a notification with the given parsed body.
    /// No `match` → always; otherwise the JSON pointer must resolve to a
    /// string equal to `equals` (event discriminators are JSON strings).
    pub fn matches(&self, body: Option<&serde_json::Value>) -> bool {
        match &self.matcher {
            None => true,
            Some(m) => body
                .and_then(|j| j.pointer(&m.json))
                .and_then(|v| v.as_str())
                .is_some_and(|s| s == m.equals),
        }
    }
}

/// Notification event matcher: `{ json: "/pointer", equals: "VALUE" }`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationMatch {
    /// RFC 6901 pointer into the notification body.
    pub json: String,
    /// Required value at that pointer (string compare).
    pub equals: String,
}

/// The originated request a [`NotificationRule`] builds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmitSpec {
    /// Diameter Command-Code (e.g. 309 PNR).
    pub command: u32,
    /// Application-Id (e.g. 16777217 Sh).
    pub application: u32,
    /// Reuse the bound session's Session-Id instead of generating a fresh one.
    /// Needed when the originated request belongs to the *same* Diameter
    /// session as the forward flow (Rx RAR/ASR share the AAR session); left
    /// false for independent pushes (Sh PNR, Cx RTR/PPR).
    #[serde(default)]
    pub reuse_session: bool,
    /// Payload AVPs. Sources resolve against the binding fields (exposed as
    /// `{identity}`/`{resource_ref}`/`{session_id}`/`{peer_host}`) and the
    /// notification body (`from_json`/`from_body`). Session-Id, Origin- and
    /// Destination-Host/Realm are set automatically by the engine.
    #[serde(default)]
    pub avps: Vec<AvpSpec>,
}

/// One `map_response` value: plugin by name, or a declarative build.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum AnswerSpec {
    /// Name of a registered plugin (computed mappings, e.g. TBCD encode).
    Plugin(String),
    /// Inline JSON→AVP answer rendered by the engine — no code involved.
    Build(AnswerBuild),
}

/// Declarative answer: result disposition plus mapped AVPs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerBuild {
    /// `Result-Code` value (RFC 6733 §7.1), e.g. 2001 / 5012.
    #[serde(default)]
    pub result_code: Option<u32>,
    /// 3GPP `Experimental-Result-Code` (TS 29.229 §6.2), rendered as the
    /// grouped `Experimental-Result` with Vendor-Id 10415, e.g. 5001.
    #[serde(default)]
    pub experimental_result: Option<u32>,
    /// AVPs appended to the answer, in order.
    #[serde(default)]
    pub avps: Vec<AvpSpec>,
}

/// One mapped answer AVP.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "AvpSpecYaml")]
pub struct AvpSpec {
    /// AVP name (resolved via the [`AvpCatalog`]; its `type` drives encoding).
    pub avp: String,
    /// Where the value comes from.
    pub source: AvpSource,
    /// When true, a missing source fails the transaction (→ 5012) instead
    /// of skipping the AVP.
    pub required: bool,
}

/// Value source of an answer AVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvpSource {
    /// Literal with `{var}` substitution.
    Value(String),
    /// JSON pointer (RFC 6901) into the last HTTP response body. Missing
    /// pointer / null → AVP skipped (unless `required`).
    FromJson {
        /// The pointer, e.g. `/serverName` or `/av5gAka/rand`.
        pointer: String,
        /// Optional byte decoding of the (string) value.
        decode: Option<Decode>,
    },
    /// The raw response body bytes (e.g. `User-Data` echo).
    FromBody,
    /// Byte concatenation of several parts (e.g. RAND‖AUTN). Any missing
    /// JSON part → AVP skipped (unless `required`).
    Concat(Vec<ConcatPart>),
    /// Nested grouped AVP. A group whose members all turn out missing is
    /// itself skipped (unless `required`).
    Group(Vec<AvpSpec>),
}

/// One part of a [`AvpSource::Concat`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "ConcatPartYaml")]
pub struct ConcatPart {
    /// JSON pointer or literal (with `{var}` substitution).
    pub source: PartSource,
    /// Optional byte decoding.
    pub decode: Option<Decode>,
}

/// Where a concat part's bytes come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartSource {
    /// JSON pointer into the response body.
    Json(String),
    /// Literal with `{var}` substitution.
    Value(String),
}

/// Byte decoding applied to string-valued sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decode {
    /// Lower/upper-case hex string → octets (auth vectors per TS 29.509).
    Hex,
}

/// Conditional guard on a stateful action: the named variable must equal
/// `equals`. Gives the otherwise-linear action list the minimal branching the
/// Ro CCR family needs (bind on INITIAL / lookup on UPDATE / unbind on
/// TERMINATION, all triggered by the same command code).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guard {
    /// Variable to test (typically a prior `extract`/`set_var`).
    pub var: String,
    /// Required value (string compare).
    pub equals: String,
}

/// `extract:` payload.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtractSpec {
    avp: String,
    #[serde(rename = "as")]
    var: String,
    #[serde(default = "default_true")]
    required: bool,
}

/// `http_request:` payload.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpRequestSpec {
    method: SbiMethod,
    nf_type: NfType,
    path: String,
    #[serde(default)]
    query: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<serde_json::Value>,
}

/// `set_var:` payload.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetVarSpec {
    from: String,
    #[serde(rename = "as")]
    var: String,
    #[serde(default)]
    map: BTreeMap<String, String>,
    #[serde(default)]
    default: Option<String>,
}

/// Wire shape of one answer AVP spec: a mapping with `avp` plus exactly one
/// source key (`value` / `from_json` / `from_body` / `concat` / `group`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AvpSpecYaml {
    avp: String,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    from_json: Option<String>,
    #[serde(default)]
    decode: Option<Decode>,
    #[serde(default)]
    from_body: Option<bool>,
    #[serde(default)]
    concat: Option<Vec<ConcatPart>>,
    #[serde(default)]
    group: Option<Vec<AvpSpec>>,
    #[serde(default)]
    required: bool,
}

impl TryFrom<AvpSpecYaml> for AvpSpec {
    type Error = String;

    fn try_from(y: AvpSpecYaml) -> Result<Self, Self::Error> {
        let keys = usize::from(y.value.is_some())
            + usize::from(y.from_json.is_some())
            + usize::from(y.from_body.is_some())
            + usize::from(y.concat.is_some())
            + usize::from(y.group.is_some());
        if keys != 1 {
            return Err(format!(
                "avp {}: exactly one of value / from_json / from_body / concat / group",
                y.avp
            ));
        }
        if y.decode.is_some() && y.from_json.is_none() {
            return Err(format!("avp {}: decode requires from_json", y.avp));
        }
        let source = if let Some(v) = y.value {
            AvpSource::Value(v)
        } else if let Some(pointer) = y.from_json {
            AvpSource::FromJson {
                pointer,
                decode: y.decode,
            }
        } else if let Some(parts) = y.concat {
            AvpSource::Concat(parts)
        } else if let Some(children) = y.group {
            AvpSource::Group(children)
        } else {
            // keys == 1 and the others are None, so from_body is present.
            if y.from_body != Some(true) {
                return Err(format!("avp {}: from_body must be true", y.avp));
            }
            AvpSource::FromBody
        };
        Ok(AvpSpec {
            avp: y.avp,
            source,
            required: y.required,
        })
    }
}

/// Wire shape of one concat part.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConcatPartYaml {
    #[serde(default)]
    from_json: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    decode: Option<Decode>,
}

impl TryFrom<ConcatPartYaml> for ConcatPart {
    type Error = String;

    fn try_from(y: ConcatPartYaml) -> Result<Self, Self::Error> {
        let source = match (y.from_json, y.value) {
            (Some(p), None) => PartSource::Json(p),
            (None, Some(v)) => PartSource::Value(v),
            _ => return Err("concat part: exactly one of from_json / value".to_owned()),
        };
        Ok(ConcatPart {
            source,
            decode: y.decode,
        })
    }
}

/// `bind:` payload.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindSpec {
    kind: String,
    identity: String,
    #[serde(default)]
    resource_json: Option<String>,
    #[serde(default)]
    resource_value: Option<String>,
    #[serde(default)]
    when: Option<Guard>,
}

/// `bind_lookup:` payload.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindLookupSpec {
    resource_as: String,
    #[serde(default)]
    when: Option<Guard>,
}

/// `unbind:` payload.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnbindSpec {
    #[serde(default)]
    resource_as: Option<String>,
    #[serde(default)]
    when: Option<Guard>,
}

/// Wire shape of one action: a mapping with exactly one recognized key.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionMap {
    #[serde(default)]
    extract: Option<ExtractSpec>,
    #[serde(default)]
    set_var: Option<SetVarSpec>,
    #[serde(default)]
    http_request: Option<HttpRequestSpec>,
    #[serde(default)]
    bind: Option<BindSpec>,
    #[serde(default)]
    bind_lookup: Option<BindLookupSpec>,
    #[serde(default)]
    unbind: Option<UnbindSpec>,
    #[serde(default)]
    map_response: Option<BTreeMap<String, AnswerSpec>>,
}

impl TryFrom<ActionMap> for Action {
    type Error = String;

    fn try_from(m: ActionMap) -> Result<Self, Self::Error> {
        let keys = usize::from(m.extract.is_some())
            + usize::from(m.set_var.is_some())
            + usize::from(m.http_request.is_some())
            + usize::from(m.bind.is_some())
            + usize::from(m.bind_lookup.is_some())
            + usize::from(m.unbind.is_some())
            + usize::from(m.map_response.is_some());
        if keys != 1 {
            return Err(
                "each action must have exactly one of extract / set_var / http_request / bind / bind_lookup / unbind / map_response"
                    .to_owned(),
            );
        }
        if let Some(e) = m.extract {
            return Ok(Action::Extract {
                avp: e.avp,
                var: e.var,
                required: e.required,
            });
        }
        if let Some(s) = m.set_var {
            return Ok(Action::SetVar {
                from: s.from,
                var: s.var,
                map: s.map,
                default: s.default,
            });
        }
        if let Some(h) = m.http_request {
            return Ok(Action::HttpRequest {
                method: h.method,
                nf_type: h.nf_type,
                path: h.path,
                query: h.query,
                body: h.body,
            });
        }
        if let Some(b) = m.bind {
            if b.resource_json.is_some() && b.resource_value.is_some() {
                return Err("bind: at most one of resource_json / resource_value".to_owned());
            }
            return Ok(Action::Bind {
                kind: b.kind,
                identity: b.identity,
                resource_json: b.resource_json,
                resource_value: b.resource_value,
                when: b.when,
            });
        }
        if let Some(l) = m.bind_lookup {
            return Ok(Action::BindLookup {
                resource_as: l.resource_as,
                when: l.when,
            });
        }
        if let Some(u) = m.unbind {
            return Ok(Action::Unbind {
                resource_as: u.resource_as,
                when: u.when,
            });
        }
        // keys == 1 and the others are None, so map_response is present.
        m.map_response
            .map(Action::MapResponse)
            .ok_or_else(|| "unreachable: counted key missing".to_owned())
    }
}

fn default_true() -> bool {
    true
}

/// One translation rule.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Unique id; appears in metrics (`iwf_translation_errors_total{rule_id}`).
    pub id: String,
    /// Matching condition.
    pub trigger: Trigger,
    /// Steps executed in order.
    pub actions: Vec<Action>,
    /// Rule version label (e.g. `3gpp-rel18`); informational + A/B key.
    pub version: String,
    /// Staged-rollout percentage [0..100]. When several rules share a
    /// trigger, a request is bucketed by End-to-End id and served by the
    /// first rule whose cumulative percentage covers the bucket.
    #[serde(default = "default_rollout")]
    pub rollout_percent: u8,
}

fn default_rollout() -> u8 {
    100
}

/// A parsed, validated rule document.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    /// All rules, in document order (order matters for A/B bucketing).
    pub rules: Vec<Rule>,
    /// Reverse-direction rules: how an inbound 5GC notification becomes an
    /// originated Diameter request (PNR/RTR/PPR/RAR/ASR). Selected by binding
    /// `kind`. Empty for interfaces with no server-push.
    #[serde(default)]
    pub notifications: Vec<NotificationRule>,
}

impl RuleSet {
    /// Parse a YAML document, validating against the builtin AVP catalog.
    pub fn from_yaml(text: &str) -> Result<RuleSet, CoreError> {
        RuleSet::from_yaml_with(text, &AvpCatalog::builtin())
    }

    /// Parse a YAML document, validating against `catalog`.
    pub fn from_yaml_with(text: &str, catalog: &AvpCatalog) -> Result<RuleSet, CoreError> {
        RuleSet::from_yaml_documents_with([text], catalog)
    }

    /// Parse and **merge** several rule documents (a directory of `*.yaml`
    /// files) into one set, then validate the whole. `rules` and
    /// `notifications` concatenate in document order; validation enforces
    /// globally-unique ids across all files, so an interface-per-file layout
    /// composes safely.
    pub fn from_yaml_documents_with<'a, I>(
        docs: I,
        catalog: &AvpCatalog,
    ) -> Result<RuleSet, CoreError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut merged = RuleSet::default();
        for text in docs {
            let set: RuleSet = serde_yaml::from_str(text)
                .map_err(|e| CoreError::Adapter(format!("rule YAML parse: {e}")))?;
            merged.rules.extend(set.rules);
            merged.notifications.extend(set.notifications);
        }
        merged.validate(catalog)?;
        Ok(merged)
    }

    /// Parse a TOML document with the same schema (builtin catalog).
    pub fn from_toml(text: &str) -> Result<RuleSet, CoreError> {
        let set: RuleSet = toml::from_str(text)
            .map_err(|e| CoreError::Adapter(format!("rule TOML parse: {e}")))?;
        set.validate(&AvpCatalog::builtin())?;
        Ok(set)
    }

    /// Structural validation beyond serde: ids unique, rollout sane,
    /// referenced AVP names known to `catalog`, exactly one `map_response`
    /// per rule and it must be last, status keys numeric or "default",
    /// inline answer specs well-formed.
    pub fn validate(&self, catalog: &AvpCatalog) -> Result<(), CoreError> {
        let mut seen = std::collections::BTreeSet::new();
        for rule in &self.rules {
            if !seen.insert(&rule.id) {
                return Err(CoreError::Adapter(format!("duplicate rule id {}", rule.id)));
            }
            if rule.rollout_percent > 100 {
                return Err(CoreError::Adapter(format!(
                    "rule {}: rollout_percent {} > 100",
                    rule.id, rule.rollout_percent
                )));
            }
            let map_positions: Vec<usize> = rule
                .actions
                .iter()
                .enumerate()
                .filter_map(|(i, a)| matches!(a, Action::MapResponse(_)).then_some(i))
                .collect();
            if map_positions.len() != 1 || map_positions[0] != rule.actions.len() - 1 {
                return Err(CoreError::Adapter(format!(
                    "rule {}: exactly one map_response is required and it must be the final action",
                    rule.id
                )));
            }
            for action in &rule.actions {
                match action {
                    Action::Extract { avp, .. } => {
                        if catalog.get(avp).is_none() {
                            return Err(CoreError::Adapter(format!(
                                "rule {}: unknown AVP name {avp}",
                                rule.id
                            )));
                        }
                    }
                    Action::MapResponse(map) => {
                        for (key, spec) in map {
                            if key != "default" && key.parse::<u16>().is_err() {
                                return Err(CoreError::Adapter(format!(
                                    "rule {}: map_response key {key} is neither a status nor 'default'",
                                    rule.id
                                )));
                            }
                            if let AnswerSpec::Build(build) = spec {
                                validate_answer_build(&rule.id, key, build, catalog)?;
                            }
                        }
                    }
                    Action::SetVar { var, .. } => {
                        if var.is_empty() {
                            return Err(CoreError::Adapter(format!(
                                "rule {}: set_var.as must be non-empty",
                                rule.id
                            )));
                        }
                    }
                    Action::Bind { kind, identity, .. } => {
                        if kind.is_empty() || identity.is_empty() {
                            return Err(CoreError::Adapter(format!(
                                "rule {}: bind.kind and bind.identity must be non-empty",
                                rule.id
                            )));
                        }
                    }
                    Action::BindLookup { resource_as, .. } => {
                        if resource_as.is_empty() {
                            return Err(CoreError::Adapter(format!(
                                "rule {}: bind_lookup.resource_as must be non-empty",
                                rule.id
                            )));
                        }
                    }
                    Action::Unbind { .. } | Action::HttpRequest { .. } => {}
                }
            }
        }
        // notifications: ids unique, command/application set, AVP specs valid.
        let mut nseen = std::collections::BTreeSet::new();
        for n in &self.notifications {
            if !nseen.insert(&n.id) {
                return Err(CoreError::Adapter(format!(
                    "duplicate notification id {}",
                    n.id
                )));
            }
            if n.bind_kind.is_empty() {
                return Err(CoreError::Adapter(format!(
                    "notification {}: bind_kind must be non-empty",
                    n.id
                )));
            }
            if n.emit.command == 0 || n.emit.application == 0 {
                return Err(CoreError::Adapter(format!(
                    "notification {}: emit.command and emit.application are required",
                    n.id
                )));
            }
            validate_avp_specs(&n.id, "emit", &n.emit.avps, catalog)?;
        }
        Ok(())
    }

    /// Select the rule for (`application`, `command`), honouring staged
    /// rollout: the request's End-to-End id is hashed into a [0,100) bucket
    /// and rules sharing the trigger are stacked by document order.
    pub fn select(&self, application: u32, command: u32, e2e: u32) -> Option<&Rule> {
        let bucket = (e2e.wrapping_mul(2654435761) >> 16) % 100; // Knuth hash → stable bucket
        let mut cumulative: u32 = 0;
        let mut fallback: Option<&Rule> = None;
        for rule in &self.rules {
            if rule.trigger.diameter_application != application
                || rule.trigger.command_code != command
            {
                continue;
            }
            fallback.get_or_insert(rule);
            cumulative += u32::from(rule.rollout_percent);
            if bucket < cumulative {
                return Some(rule);
            }
        }
        // Buckets above the cumulative coverage fall back to the first
        // matching rule so partial rollouts never drop traffic.
        fallback
    }
}

/// Validate one inline answer spec against the catalog: exactly one result
/// disposition, then the AVP specs (names known, `group` ⇔ Grouped).
fn validate_answer_build(
    rule_id: &str,
    status_key: &str,
    build: &AnswerBuild,
    catalog: &AvpCatalog,
) -> Result<(), CoreError> {
    if build.result_code.is_some() == build.experimental_result.is_some() {
        return Err(CoreError::Adapter(format!(
            "rule {rule_id} ({status_key}): exactly one of result_code / experimental_result"
        )));
    }
    validate_avp_specs(rule_id, status_key, &build.avps, catalog)
}

/// Validate a list of [`AvpSpec`]s (answer `avps` or notification `emit.avps`):
/// every AVP name is known to the catalog and `group:` is used exactly for
/// Grouped AVPs. Recurses into groups.
fn validate_avp_specs(
    id: &str,
    scope: &str,
    specs: &[AvpSpec],
    catalog: &AvpCatalog,
) -> Result<(), CoreError> {
    for spec in specs {
        let def = catalog.get(&spec.avp).ok_or_else(|| {
            CoreError::Adapter(format!("{id} ({scope}): unknown AVP name {}", spec.avp))
        })?;
        match &spec.source {
            AvpSource::Group(children) => {
                if def.kind != AvpKind::Grouped {
                    return Err(CoreError::Adapter(format!(
                        "{id} ({scope}): {} is not Grouped",
                        spec.avp
                    )));
                }
                validate_avp_specs(id, scope, children, catalog)?;
            }
            _ if def.kind == AvpKind::Grouped => {
                return Err(CoreError::Adapter(format!(
                    "{id} ({scope}): {} is Grouped and needs `group:`",
                    spec.avp
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Hot-swappable rule holder. Readers pay one atomic load per transaction;
/// writers (admin API / file watcher) validate — against the *current*
/// dictionary in the shared [`CatalogStore`] — then swap atomically, so a bad
/// document can never become active.
#[derive(Debug, Default)]
pub struct RuleStore {
    current: ArcSwap<RuleSet>,
    catalog: Arc<CatalogStore>,
}

impl RuleStore {
    /// Store seeded with `initial`, validating reloads against the builtin
    /// catalog.
    pub fn new(initial: RuleSet) -> Self {
        RuleStore::with_catalog_store(initial, Arc::new(CatalogStore::default()))
    }

    /// Store seeded with `initial`, validating reloads against a private
    /// snapshot of `catalog` (not hot-reloadable; convenient for tests).
    pub fn with_catalog(initial: RuleSet, catalog: Arc<AvpCatalog>) -> Self {
        RuleStore::with_catalog_store(
            initial,
            Arc::new(CatalogStore::new(catalog.as_ref().clone())),
        )
    }

    /// Store seeded with `initial`, sharing `catalog` with the engine and the
    /// admin dictionary-reload endpoint so a dictionary swap is seen here too.
    pub fn with_catalog_store(initial: RuleSet, catalog: Arc<CatalogStore>) -> Self {
        RuleStore {
            current: ArcSwap::from_pointee(initial),
            catalog,
        }
    }

    /// The shared catalog holder (so the engine and admin API can share it).
    pub fn catalog(&self) -> Arc<CatalogStore> {
        self.catalog.clone()
    }

    /// Current snapshot (cheap; clone of an `Arc`).
    pub fn load(&self) -> Arc<RuleSet> {
        self.current.load_full()
    }

    /// Validate and atomically activate a new YAML document (or directory of
    /// documents). On error the previous rules stay active.
    pub fn reload_yaml(&self, text: &str) -> Result<usize, CoreError> {
        let set = RuleSet::from_yaml_with(text, &self.catalog.load())?;
        let n = set.rules.len();
        self.current.store(Arc::new(set));
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
rules:
  - id: cx_uar_to_udm_identity_query
    trigger:
      diameter_application: 16777216
      command_code: 300
    actions:
      - extract: { avp: "User-Name", as: impi }
      - extract: { avp: "Public-Identity", as: impu }
      - http_request:
          method: GET
          nf_type: UDM
          path: "/nudm-uecm/v1/{impi}/registrations"
          query:
            impu: "{impu}"
      - map_response:
          200: build_uaa_success
          404: build_uaa_user_unknown
          503: build_uaa_unable_to_comply
    version: "3gpp-rel18"
"#;

    #[test]
    fn parses_prompt_schema_exactly() {
        let set = RuleSet::from_yaml(SAMPLE).expect("parse");
        assert_eq!(set.rules.len(), 1);
        let rule = &set.rules[0];
        assert_eq!(rule.id, "cx_uar_to_udm_identity_query");
        assert_eq!(rule.trigger.diameter_application, 16_777_216);
        assert_eq!(rule.trigger.command_code, 300);
        assert_eq!(rule.rollout_percent, 100);
        assert_eq!(rule.actions.len(), 4);
        match &rule.actions[0] {
            Action::Extract { avp, var, required } => {
                assert_eq!(avp, "User-Name");
                assert_eq!(var, "impi");
                assert!(*required);
            }
            other => panic!("expected extract, got {other:?}"),
        }
        match &rule.actions[2] {
            Action::HttpRequest {
                method,
                nf_type,
                path,
                query,
                body,
            } => {
                assert_eq!(*method, SbiMethod::Get);
                assert_eq!(*nf_type, NfType::Udm);
                assert_eq!(path, "/nudm-uecm/v1/{impi}/registrations");
                assert_eq!(query.get("impu").map(String::as_str), Some("{impu}"));
                assert!(body.is_none());
            }
            other => panic!("expected http_request, got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_ids() {
        let doubled = format!("{SAMPLE}{}", SAMPLE.replacen("rules:\n", "", 1));
        assert!(RuleSet::from_yaml(&doubled).is_err());
    }

    #[test]
    fn rejects_unknown_avp_name() {
        let bad = SAMPLE.replace("User-Name", "No-Such-AVP");
        assert!(RuleSet::from_yaml(&bad).is_err());
    }

    #[test]
    fn inline_answer_specs_parse_alongside_plugins() {
        let doc = r#"
rules:
  - id: r1
    trigger: { diameter_application: 16777216, command_code: 302 }
    actions:
      - map_response:
          200:
            result_code: 2001
            avps:
              - { avp: Server-Name, from_json: "/serverName", required: true }
              - avp: SIP-Auth-Data-Item
                group:
                  - { avp: SIP-Authentication-Scheme, value: "Digest-AKAv1-MD5" }
                  - avp: SIP-Authenticate
                    concat:
                      - { from_json: "/rand", decode: hex }
                      - { from_json: "/autn", decode: hex }
          404: { experimental_result: 5001 }
          default: build_unable_to_comply       # plugins still mix in
    version: v1
"#;
        let set = RuleSet::from_yaml(doc).expect("parse");
        match &set.rules[0].actions[0] {
            Action::MapResponse(map) => {
                assert!(matches!(map.get("200"), Some(AnswerSpec::Build(_))));
                assert!(matches!(
                    map.get("default"),
                    Some(AnswerSpec::Plugin(p)) if p == "build_unable_to_comply"
                ));
            }
            other => panic!("expected map_response, got {other:?}"),
        }
    }

    #[test]
    fn inline_answer_specs_are_validated() {
        let with_default = |spec: &str| {
            format!(
                r#"
rules:
  - id: r1
    trigger: {{ diameter_application: 1, command_code: 2 }}
    actions:
      - map_response:
          default: {spec}
    version: v1
"#
            )
        };
        // Well-formed minimal specs.
        assert!(RuleSet::from_yaml(&with_default("{ result_code: 5012 }")).is_ok());
        assert!(RuleSet::from_yaml(&with_default("{ experimental_result: 5001 }")).is_ok());
        // Unknown AVP name.
        assert!(RuleSet::from_yaml(&with_default(
            "{ result_code: 2001, avps: [ { avp: No-Such, value: x } ] }"
        ))
        .is_err());
        // Grouped AVP requires `group:`.
        assert!(RuleSet::from_yaml(&with_default(
            "{ result_code: 2001, avps: [ { avp: SIP-Auth-Data-Item, value: x } ] }"
        ))
        .is_err());
        // `group:` on a non-grouped AVP.
        assert!(RuleSet::from_yaml(&with_default(
            "{ result_code: 2001, avps: [ { avp: Server-Name, group: [] } ] }"
        ))
        .is_err());
        // Exactly one result disposition.
        assert!(RuleSet::from_yaml(&with_default(
            "{ result_code: 2001, experimental_result: 5001 }"
        ))
        .is_err());
        assert!(RuleSet::from_yaml(&with_default("{ avps: [] }")).is_err());
        // Exactly one source per AVP (rejected at deserialization).
        assert!(RuleSet::from_yaml(&with_default(
            "{ result_code: 2001, avps: [ { avp: Server-Name, value: x, from_body: true } ] }"
        ))
        .is_err());
        assert!(RuleSet::from_yaml(&with_default(
            "{ result_code: 2001, avps: [ { avp: Server-Name } ] }"
        ))
        .is_err());
        // decode requires from_json.
        assert!(RuleSet::from_yaml(&with_default(
            "{ result_code: 2001, avps: [ { avp: Server-Name, value: x, decode: hex } ] }"
        ))
        .is_err());
    }

    #[test]
    fn custom_catalog_extends_the_dsl() {
        let catalog = AvpCatalog::from_yaml(
            r#"
interfaces:
  foo:
    avps:
      - { name: Foo-Token, code: 9001, vendor: 4242, type: UTF8String }
"#,
        )
        .expect("catalog");
        let doc = r#"
rules:
  - id: r1
    trigger: { diameter_application: 1, command_code: 2 }
    actions:
      - extract: { avp: "Foo-Token", as: tok }
      - map_response:
          default: { result_code: 2001, avps: [ { avp: Foo-Token, value: "{tok}" } ] }
    version: v1
"#;
        // Unknown to the builtin catalog…
        assert!(RuleSet::from_yaml(doc).is_err());
        // …valid against the loaded dictionary.
        RuleSet::from_yaml_with(doc, &catalog).expect("valid with custom catalog");
        // Reloads validate against the store's catalog, not the builtin.
        let store = RuleStore::with_catalog(RuleSet::default(), Arc::new(catalog));
        assert_eq!(store.reload_yaml(doc).expect("reload"), 1);
    }

    #[test]
    fn merges_multiple_rule_documents() {
        // One file per interface, merged into a single validated set.
        let cx = r#"
rules:
  - id: cx_rule
    trigger: { diameter_application: 16777216, command_code: 300 }
    actions:
      - map_response: { default: build_success }
    version: v1
"#;
        let sh = r#"
rules:
  - id: sh_rule
    trigger: { diameter_application: 16777217, command_code: 306 }
    actions:
      - map_response: { default: build_success }
    version: v1
notifications:
  - id: sh_pnr
    bind_kind: sh
    emit: { command: 309, application: 16777217, avps: [ { avp: User-Name, value: "{identity}" } ] }
"#;
        let set =
            RuleSet::from_yaml_documents_with([cx, sh], &AvpCatalog::builtin()).expect("merge");
        assert_eq!(set.rules.len(), 2);
        assert_eq!(set.notifications.len(), 1);

        // A duplicate id *across* files is caught by whole-set validation.
        assert!(RuleSet::from_yaml_documents_with([cx, cx], &AvpCatalog::builtin()).is_err());
    }

    #[test]
    fn rejects_missing_map_response() {
        let bad = r#"
rules:
  - id: r1
    trigger: { diameter_application: 1, command_code: 2 }
    actions:
      - extract: { avp: "User-Name", as: x }
    version: v1
"#;
        assert!(RuleSet::from_yaml(bad).is_err());
    }

    #[test]
    fn notifications_and_bind_parse_and_validate() {
        let doc = r#"
rules:
  - id: sh_snr
    trigger: { diameter_application: 16777217, command_code: 308 }
    actions:
      - extract: { avp: "User-Name", as: id }
      - http_request: { method: POST, nf_type: HSS, path: "/x/{id}/subscriptions" }
      - bind: { kind: sh, identity: "{id}" }
      - map_response: { default: { result_code: 2001 } }
    version: v1
notifications:
  - id: sh_pnr
    bind_kind: sh
    emit:
      command: 309
      application: 16777217
      avps:
        - { avp: User-Name, value: "{identity}" }
        - { avp: User-Data, from_body: true }
"#;
        let set = RuleSet::from_yaml(doc).expect("parse");
        assert_eq!(set.notifications.len(), 1);
        assert_eq!(set.notifications[0].emit.command, 309);
        match &set.rules[0].actions[2] {
            Action::Bind { kind, identity, .. } => {
                assert_eq!(kind, "sh");
                assert_eq!(identity, "{id}");
            }
            other => panic!("expected bind, got {other:?}"),
        }
    }

    #[test]
    fn notification_rules_are_validated() {
        let with_notif = |emit: &str| {
            format!(
                r#"
rules: []
notifications:
  - id: n1
    bind_kind: sh
    emit:
{emit}
"#
            )
        };
        // Unknown AVP in emit.
        assert!(RuleSet::from_yaml(&with_notif(
            "      command: 309\n      application: 16777217\n      avps: [ { avp: No-Such, value: x } ]"
        ))
        .is_err());
        // Missing command/application.
        assert!(RuleSet::from_yaml(&with_notif("      application: 16777217")).is_err());
        // Grouped AVP without `group:`.
        assert!(RuleSet::from_yaml(&with_notif(
            "      command: 309\n      application: 16777217\n      avps: [ { avp: SIP-Auth-Data-Item, value: x } ]"
        ))
        .is_err());
        // Well-formed.
        assert!(RuleSet::from_yaml(&with_notif(
            "      command: 309\n      application: 16777217\n      avps: [ { avp: User-Name, value: \"{identity}\" } ]"
        ))
        .is_ok());
        // bind action requires kind + identity (empty identity rejected).
        let bad_bind = r#"
rules:
  - id: r
    trigger: { diameter_application: 1, command_code: 2 }
    actions:
      - bind: { kind: sh, identity: "" }
      - map_response: { default: { result_code: 2001 } }
    version: v1
"#;
        assert!(RuleSet::from_yaml(bad_bind).is_err());
    }

    #[test]
    fn select_matches_trigger() {
        let set = RuleSet::from_yaml(SAMPLE).expect("parse");
        assert!(set.select(16_777_216, 300, 1).is_some());
        assert!(set.select(16_777_216, 301, 1).is_none());
    }

    #[test]
    fn ab_rollout_buckets_split_traffic() {
        let ab = r#"
rules:
  - id: v19
    trigger: { diameter_application: 16777216, command_code: 300 }
    actions:
      - map_response: { default: build_uaa_success }
    version: "3gpp-rel19"
    rollout_percent: 30
  - id: v18
    trigger: { diameter_application: 16777216, command_code: 300 }
    actions:
      - map_response: { default: build_uaa_success }
    version: "3gpp-rel18"
    rollout_percent: 70
"#;
        let set = RuleSet::from_yaml(ab).expect("parse");
        let (mut new, mut old) = (0u32, 0u32);
        for e2e in 0..1000u32 {
            match set.select(16_777_216, 300, e2e).expect("rule").id.as_str() {
                "v19" => new += 1,
                _ => old += 1,
            }
        }
        assert!(new > 150 && new < 450, "v19 got {new}/1000");
        assert!(old > 550, "v18 got {old}/1000");
        // Same e2e always lands on the same rule (sticky bucketing).
        let first = set.select(16_777_216, 300, 42).expect("rule").id.clone();
        for _ in 0..10 {
            assert_eq!(set.select(16_777_216, 300, 42).expect("rule").id, first);
        }
    }

    #[test]
    fn hot_reload_keeps_old_rules_on_error() {
        let store = RuleStore::new(RuleSet::from_yaml(SAMPLE).expect("parse"));
        assert!(store.reload_yaml("rules: [ { broken").is_err());
        assert_eq!(store.load().rules.len(), 1, "previous rules still active");
        let two = SAMPLE.replace(
            "cx_uar_to_udm_identity_query",
            "cx_uar_to_udm_identity_query_v2",
        );
        store.reload_yaml(&two).expect("valid reload");
        assert_eq!(store.load().rules[0].id, "cx_uar_to_udm_identity_query_v2");
    }
}
