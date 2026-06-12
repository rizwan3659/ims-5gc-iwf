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

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use iwf_core::error::CoreError;
use iwf_core::nf::NfType;
use iwf_core::ports::SbiMethod;
use serde::Deserialize;

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
        /// AVP name (resolved via [`crate::mapping::avp_by_name`]).
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
    /// Map the most recent HTTP status to a named answer builder
    /// (a [`crate::plugin::TranslationPlugin`] registered under that name).
    /// The key `"default"` handles unlisted statuses.
    MapResponse(BTreeMap<String, String>),
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

/// Wire shape of one action: a mapping with exactly one recognized key.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionMap {
    #[serde(default)]
    extract: Option<ExtractSpec>,
    #[serde(default)]
    http_request: Option<HttpRequestSpec>,
    #[serde(default)]
    map_response: Option<BTreeMap<String, String>>,
}

impl TryFrom<ActionMap> for Action {
    type Error = String;

    fn try_from(m: ActionMap) -> Result<Self, Self::Error> {
        let keys = usize::from(m.extract.is_some())
            + usize::from(m.http_request.is_some())
            + usize::from(m.map_response.is_some());
        if keys != 1 {
            return Err(
                "each action must have exactly one of extract / http_request / map_response"
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
        if let Some(h) = m.http_request {
            return Ok(Action::HttpRequest {
                method: h.method,
                nf_type: h.nf_type,
                path: h.path,
                query: h.query,
                body: h.body,
            });
        }
        // keys == 1 and the other two are None, so map_response is present.
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
}

impl RuleSet {
    /// Parse a YAML document.
    pub fn from_yaml(text: &str) -> Result<RuleSet, CoreError> {
        let set: RuleSet = serde_yaml::from_str(text)
            .map_err(|e| CoreError::Adapter(format!("rule YAML parse: {e}")))?;
        set.validate()?;
        Ok(set)
    }

    /// Parse a TOML document with the same schema.
    pub fn from_toml(text: &str) -> Result<RuleSet, CoreError> {
        let set: RuleSet = toml::from_str(text)
            .map_err(|e| CoreError::Adapter(format!("rule TOML parse: {e}")))?;
        set.validate()?;
        Ok(set)
    }

    /// Structural validation beyond serde: ids unique, rollout sane,
    /// referenced AVP names known, exactly one `map_response` per rule and it
    /// must be last, status keys numeric or "default".
    pub fn validate(&self) -> Result<(), CoreError> {
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
                        if crate::mapping::avp_by_name(avp).is_none() {
                            return Err(CoreError::Adapter(format!(
                                "rule {}: unknown AVP name {avp}",
                                rule.id
                            )));
                        }
                    }
                    Action::MapResponse(map) => {
                        for key in map.keys() {
                            if key != "default" && key.parse::<u16>().is_err() {
                                return Err(CoreError::Adapter(format!(
                                    "rule {}: map_response key {key} is neither a status nor 'default'",
                                    rule.id
                                )));
                            }
                        }
                    }
                    Action::HttpRequest { .. } => {}
                }
            }
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

/// Hot-swappable rule holder. Readers pay one atomic load per transaction;
/// writers (admin API / file watcher) validate then swap atomically, so a
/// bad document can never become active.
#[derive(Debug, Default)]
pub struct RuleStore {
    current: ArcSwap<RuleSet>,
}

impl RuleStore {
    /// Store seeded with `initial`.
    pub fn new(initial: RuleSet) -> Self {
        RuleStore {
            current: ArcSwap::from_pointee(initial),
        }
    }

    /// Current snapshot (cheap; clone of an `Arc`).
    pub fn load(&self) -> Arc<RuleSet> {
        self.current.load_full()
    }

    /// Validate and atomically activate a new YAML document. On error the
    /// previous rules stay active.
    pub fn reload_yaml(&self, text: &str) -> Result<usize, CoreError> {
        let set = RuleSet::from_yaml(text)?;
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
