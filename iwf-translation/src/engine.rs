//! The translation engine: executes the active rule for an incoming
//! Diameter request, driving SBI calls through the [`SbaPort`] and building
//! the Diameter answer via the named plugin.

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use iwf_core::error::CoreError;
use iwf_core::ports::{SbaPort, SbiRequest, SbiResponse};
use iwf_diameter::message::Message;

use crate::mapping::avp_by_name;
use crate::plugin::{PluginRegistry, TranslationContext};
use crate::rule::{Action, Rule, RuleStore};

/// Engine wiring: rule store (hot-swappable), plugin registry, SBA port and
/// the local Diameter identity used in answers.
pub struct TranslationEngine {
    rules: Arc<RuleStore>,
    plugins: PluginRegistry,
    sba: Arc<dyn SbaPort>,
    origin_host: String,
    origin_realm: String,
}

impl std::fmt::Debug for TranslationEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TranslationEngine")
            .field("origin_host", &self.origin_host)
            .field("origin_realm", &self.origin_realm)
            .finish()
    }
}

impl TranslationEngine {
    /// Construct the engine.
    pub fn new(
        rules: Arc<RuleStore>,
        plugins: PluginRegistry,
        sba: Arc<dyn SbaPort>,
        origin_host: impl Into<String>,
        origin_realm: impl Into<String>,
    ) -> Self {
        TranslationEngine {
            rules,
            plugins,
            sba,
            origin_host: origin_host.into(),
            origin_realm: origin_realm.into(),
        }
    }

    /// Translate one Diameter request into its answer.
    ///
    /// Errors are returned to the Diameter front-end, which renders them as
    /// protocol answers (5005 for missing AVPs, 3004 under shed, 5012
    /// otherwise) — the engine itself never panics or unwraps.
    pub async fn translate(
        &self,
        request: &Message,
        correlation_id: &str,
    ) -> Result<Message, CoreError> {
        let snapshot = self.rules.load();
        let rule = snapshot
            .select(
                request.header.application,
                request.header.command,
                request.header.end_to_end,
            )
            .ok_or(CoreError::NoRule {
                application: request.header.application,
                command: request.header.command,
            })?;

        tracing::debug!(
            rule_id = %rule.id,
            rule_version = %rule.version,
            correlation_id,
            "translating request"
        );
        self.execute(rule, request, correlation_id).await
    }

    async fn execute(
        &self,
        rule: &Rule,
        request: &Message,
        correlation_id: &str,
    ) -> Result<Message, CoreError> {
        let mut ctx = TranslationContext {
            request: request.clone(),
            vars: BTreeMap::new(),
            response: None,
            origin_host: self.origin_host.clone(),
            origin_realm: self.origin_realm.clone(),
        };

        for action in &rule.actions {
            match action {
                Action::Extract { avp, var, required } => {
                    // Name validity is guaranteed by RuleSet::validate.
                    let (code, vendor) =
                        avp_by_name(avp).ok_or(CoreError::MissingElement("known AVP name"))?;
                    match request.find(code, vendor) {
                        Some(found) => {
                            let value = found
                                .as_utf8()
                                .map_err(|e| CoreError::Adapter(format!("{avp}: {e}")))?;
                            ctx.vars.insert(var.clone(), value.to_owned());
                        }
                        None if *required => {
                            return Err(CoreError::MissingElement("required AVP for rule"));
                        }
                        None => {}
                    }
                }

                Action::HttpRequest {
                    method,
                    nf_type,
                    path,
                    query,
                    body,
                } => {
                    let path = substitute(path, &ctx.vars)?;
                    let mut q = BTreeMap::new();
                    for (k, v) in query {
                        q.insert(k.clone(), substitute(v, &ctx.vars)?);
                    }
                    let body_bytes = match body {
                        Some(template) => {
                            let rendered = substitute_json(template, &ctx.vars)?;
                            Some(Bytes::from(rendered.to_string()))
                        }
                        None => None,
                    };
                    let response: SbiResponse = self
                        .sba
                        .send(SbiRequest {
                            method: *method,
                            nf_type: *nf_type,
                            path,
                            query: q,
                            body: body_bytes,
                            correlation_id: correlation_id.to_owned(),
                        })
                        .await?;
                    ctx.response = Some(response);
                }

                Action::MapResponse(map) => {
                    let status = ctx.response.as_ref().map(|r| r.status);
                    let builder_name = status
                        .and_then(|s| map.get(&s.to_string()))
                        .or_else(|| map.get("default"))
                        .ok_or_else(|| {
                            CoreError::UnableToComply(format!(
                                "rule {}: no mapping for status {status:?} and no default",
                                rule.id
                            ))
                        })?;
                    let plugin = self.plugins.get(builder_name).ok_or_else(|| {
                        CoreError::UnableToComply(format!(
                            "rule {}: unknown builder {builder_name}",
                            rule.id
                        ))
                    })?;
                    return plugin.build_answer(&ctx);
                }
            }
        }

        // RuleSet::validate guarantees a trailing map_response, so this is
        // unreachable for validated rules; defend anyway.
        Err(CoreError::UnableToComply(format!(
            "rule {} ended without map_response",
            rule.id
        )))
    }
}

/// Replace `{var}` placeholders. Unknown variables fail the transaction —
/// silently passing a literal `{impi}` to a UDM would be worse.
///
/// Braces are escaped `format!`-style: `{{` and `}}` emit literal `{`/`}`,
/// so JSON-valued templates (e.g. the SBI `plmn-id` query
/// `{{"mcc":"999","mnc":"70"}}`) pass through without being mistaken for
/// placeholders.
fn substitute(template: &str, vars: &BTreeMap<String, String>) -> Result<String, CoreError> {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' if bytes.get(i + 1) == Some(&b'{') => {
                out.push('{');
                i += 2;
            }
            b'}' if bytes.get(i + 1) == Some(&b'}') => {
                out.push('}');
                i += 2;
            }
            b'}' => {
                return Err(CoreError::Adapter(format!(
                    "unmatched '}}' in template {template}"
                )))
            }
            b'{' => {
                let after = &template[i + 1..];
                let end = after.find('}').ok_or_else(|| {
                    CoreError::Adapter(format!("unterminated placeholder in {template}"))
                })?;
                let name = &after[..end];
                let value = vars
                    .get(name)
                    .ok_or_else(|| CoreError::Adapter(format!("unbound variable {{{name}}}")))?;
                out.push_str(value);
                i += 1 + end + 1;
            }
            _ => {
                // Copy one UTF-8 char (templates are valid &str).
                let ch = template[i..].chars().next().unwrap_or('\u{FFFD}');
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    Ok(out)
}

/// Apply [`substitute`] to every string scalar in a JSON template.
fn substitute_json(
    template: &serde_json::Value,
    vars: &BTreeMap<String, String>,
) -> Result<serde_json::Value, CoreError> {
    Ok(match template {
        serde_json::Value::String(s) => serde_json::Value::String(substitute(s, vars)?),
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .iter()
                .map(|v| substitute_json(v, vars))
                .collect::<Result<_, _>>()?,
        ),
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k.clone(), substitute_json(v, vars)?);
            }
            serde_json::Value::Object(out)
        }
        other => other.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use iwf_diameter::avp::AvpValue;
    use iwf_diameter::dictionary as dict;
    use iwf_diameter::message::MessageBuilder;
    use std::sync::Mutex;

    /// Mock SBA port: records the request, returns a programmed response.
    struct MockSba {
        status: u16,
        body: serde_json::Value,
        seen: Mutex<Vec<SbiRequest>>,
    }

    #[async_trait]
    impl SbaPort for MockSba {
        async fn send(&self, request: SbiRequest) -> Result<SbiResponse, CoreError> {
            self.seen
                .lock()
                .map_err(|_| CoreError::Adapter("mock poisoned".to_owned()))?
                .push(request);
            Ok(SbiResponse {
                status: self.status,
                body: Bytes::from(self.body.to_string()),
            })
        }
    }

    const UAR_RULE: &str = r#"
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

    fn engine_with(status: u16, body: serde_json::Value) -> (TranslationEngine, Arc<MockSba>) {
        let sba = Arc::new(MockSba {
            status,
            body,
            seen: Mutex::new(Vec::new()),
        });
        let store = Arc::new(RuleStore::new(
            crate::rule::RuleSet::from_yaml(UAR_RULE).expect("rules"),
        ));
        let engine = TranslationEngine::new(
            store,
            PluginRegistry::with_builtins(),
            sba.clone(),
            "iwf.example.org",
            "example.org",
        );
        (engine, sba)
    }

    fn uar() -> Message {
        MessageBuilder::request(dict::CMD_UAR, dict::APP_CX)
            .ids(7, 8)
            .std(dict::AVP_SESSION_ID, AvpValue::Utf8("s;1;1".to_owned()))
            .std(
                dict::AVP_USER_NAME,
                AvpValue::Utf8("alice@ims.example.org".to_owned()),
            )
            .tgpp(
                dict::AVP_PUBLIC_IDENTITY,
                AvpValue::Utf8("sip:alice@example.org".to_owned()),
            )
            .build()
    }

    #[tokio::test]
    async fn uar_200_yields_uaa_success_and_correct_sbi_request() {
        let (engine, sba) = engine_with(
            200,
            serde_json::json!({"scscfName": "sip:scscf1.example.org"}),
        );
        let answer = engine.translate(&uar(), "corr-1").await.expect("answer");
        assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));
        assert_eq!(answer.header.hop_by_hop, 7);

        let seen = sba.seen.lock().expect("mock lock");
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].path,
            "/nudm-uecm/v1/alice@ims.example.org/registrations"
        );
        assert_eq!(
            seen[0].query.get("impu").map(String::as_str),
            Some("sip:alice@example.org")
        );
        assert_eq!(seen[0].correlation_id, "corr-1");
    }

    #[tokio::test]
    async fn uar_404_yields_user_unknown() {
        let (engine, _) = engine_with(404, serde_json::json!({}));
        let answer = engine.translate(&uar(), "corr-2").await.expect("answer");
        assert!(answer.find(dict::AVP_EXPERIMENTAL_RESULT, None).is_some());
    }

    #[tokio::test]
    async fn uar_503_yields_unable_to_comply() {
        let (engine, _) = engine_with(503, serde_json::json!({}));
        let answer = engine.translate(&uar(), "corr-3").await.expect("answer");
        assert_eq!(answer.result_code(), Some(dict::RC_UNABLE_TO_COMPLY));
    }

    #[tokio::test]
    async fn unmapped_status_without_default_fails_closed() {
        let (engine, _) = engine_with(418, serde_json::json!({}));
        assert!(engine.translate(&uar(), "corr-4").await.is_err());
    }

    #[tokio::test]
    async fn missing_required_avp_is_rejected() {
        let (engine, _) = engine_with(200, serde_json::json!({}));
        let no_user = MessageBuilder::request(dict::CMD_UAR, dict::APP_CX)
            .ids(1, 1)
            .build();
        assert!(matches!(
            engine.translate(&no_user, "corr-5").await,
            Err(CoreError::MissingElement(_))
        ));
    }

    #[tokio::test]
    async fn unknown_command_has_no_rule() {
        let (engine, _) = engine_with(200, serde_json::json!({}));
        let par = MessageBuilder::request(999, dict::APP_CX).ids(1, 1).build();
        assert!(matches!(
            engine.translate(&par, "corr-6").await,
            Err(CoreError::NoRule { .. })
        ));
    }

    #[test]
    fn substitution_rules() {
        let mut vars = BTreeMap::new();
        vars.insert("impi".to_owned(), "alice@realm".to_owned());
        assert_eq!(
            substitute("/x/{impi}/y", &vars).expect("ok"),
            "/x/alice@realm/y"
        );
        assert!(substitute("/x/{missing}", &vars).is_err());
        assert!(substitute("/x/{impi", &vars).is_err());
        assert_eq!(substitute("plain", &vars).expect("ok"), "plain");
    }

    #[test]
    fn substitution_escapes_braces_for_json_values() {
        let mut vars = BTreeMap::new();
        vars.insert("supi".to_owned(), "imsi-999700000000001".to_owned());
        // The Open5GS plmn-id query value, with {{ }} escaping the literal
        // JSON braces and {supi} still expanding.
        assert_eq!(
            substitute(r#"{{"mcc":"999","mnc":"70"}}"#, &vars).expect("ok"),
            r#"{"mcc":"999","mnc":"70"}"#
        );
        assert_eq!(
            substitute(r#"/nudm-sdm/v2/{supi}/am-data"#, &vars).expect("ok"),
            "/nudm-sdm/v2/imsi-999700000000001/am-data"
        );
        // An unescaped lone '}' is a template error.
        assert!(substitute("oops}", &vars).is_err());
    }
}
