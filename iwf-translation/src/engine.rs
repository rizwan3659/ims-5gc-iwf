//! The translation engine: executes the active rule for an incoming
//! Diameter request, driving SBI calls through the [`SbaPort`] and building
//! the Diameter answer via the named plugin.

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use iwf_core::error::CoreError;
use iwf_core::ports::{SbaPort, SbiRequest, SbiResponse};
use iwf_diameter::message::Message;

use iwf_diameter::avp::{avp, avp_vendor, Avp, AvpValue};
use iwf_diameter::dictionary as dict;

use crate::catalog::{AvpCatalog, AvpKind};
use crate::plugin::{experimental_result, PluginRegistry, TranslationContext};
use crate::rule::{
    Action, AnswerBuild, AnswerSpec, AvpSource, AvpSpec, ConcatPart, Decode, PartSource, Rule,
    RuleStore,
};

/// Engine wiring: rule store (hot-swappable), plugin registry, AVP catalog,
/// SBA port and the local Diameter identity used in answers.
pub struct TranslationEngine {
    rules: Arc<RuleStore>,
    plugins: PluginRegistry,
    catalog: Arc<AvpCatalog>,
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
            catalog: Arc::new(AvpCatalog::builtin()),
            sba,
            origin_host: origin_host.into(),
            origin_realm: origin_realm.into(),
        }
    }

    /// Replace the builtin AVP catalog with a dictionary-loaded one (pass
    /// the same `Arc` the [`RuleStore`] validates against).
    pub fn with_catalog(mut self, catalog: Arc<AvpCatalog>) -> Self {
        self.catalog = catalog;
        self
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
                    let def = self
                        .catalog
                        .get(avp)
                        .ok_or(CoreError::MissingElement("known AVP name"))?;
                    match request.find(def.code, def.vendor) {
                        Some(found) => {
                            // Type-aware: integer AVPs (Server-Assignment-Type,
                            // Data-Reference, ...) are rendered as their decimal
                            // string so `set_var` tables can key on them. We
                            // can't infer this from bytes — a 4-octet
                            // Enumerated is often valid UTF-8 — so the catalog
                            // type decides.
                            let value = if def.kind.is_integer() {
                                found
                                    .as_enum()
                                    .map(|i| i.to_string())
                                    .or_else(|_| found.as_u32().map(|u| u.to_string()))
                                    .map_err(|e| CoreError::Adapter(format!("{avp}: {e}")))?
                            } else {
                                found
                                    .as_utf8()
                                    .map_err(|e| CoreError::Adapter(format!("{avp}: {e}")))?
                                    .to_owned()
                            };
                            ctx.vars.insert(var.clone(), value);
                        }
                        None if *required => {
                            return Err(CoreError::MissingElement("required AVP for rule"));
                        }
                        None => {}
                    }
                }

                Action::SetVar {
                    from,
                    var,
                    map,
                    default,
                } => {
                    // Two modes:
                    //  * non-empty map → map-or-default: mapped value if the
                    //    source matches a key, else `default` (used for
                    //    Server-Assignment-Type → uecmOp, Data-Reference → res).
                    //  * empty map → passthrough-or-default: the source value
                    //    if present, else `default` (used to guarantee an
                    //    optional var like scscfName is always bound).
                    let mapped = if map.is_empty() {
                        ctx.vars.get(from).or(default.as_ref()).cloned()
                    } else {
                        ctx.vars
                            .get(from)
                            .and_then(|v| map.get(v))
                            .or(default.as_ref())
                            .cloned()
                    };
                    if let Some(value) = mapped {
                        ctx.vars.insert(var.clone(), value);
                    }
                    // No match and no default → variable left unset; a later
                    // `{var}` reference will fail the transaction loudly rather
                    // than silently calling the wrong NF resource.
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
                    let spec = status
                        .and_then(|s| map.get(&s.to_string()))
                        .or_else(|| map.get("default"))
                        .ok_or_else(|| {
                            CoreError::UnableToComply(format!(
                                "rule {}: no mapping for status {status:?} and no default",
                                rule.id
                            ))
                        })?;
                    return match spec {
                        AnswerSpec::Plugin(builder_name) => {
                            let plugin = self.plugins.get(builder_name).ok_or_else(|| {
                                CoreError::UnableToComply(format!(
                                    "rule {}: unknown builder {builder_name}",
                                    rule.id
                                ))
                            })?;
                            plugin.build_answer(&ctx)
                        }
                        AnswerSpec::Build(build) => self.build_inline(&rule.id, build, &ctx),
                    };
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

    /// Render a declarative `map_response` answer: the result disposition
    /// plus each mapped AVP, encoded per its catalog type. The declarative
    /// path is what lets a new interface ship as YAML only.
    fn build_inline(
        &self,
        rule_id: &str,
        build: &AnswerBuild,
        ctx: &TranslationContext,
    ) -> Result<Message, CoreError> {
        let mut b = ctx.answer();
        if let Some(rc) = build.result_code {
            b = b.std(dict::AVP_RESULT_CODE, AvpValue::U32(rc));
        }
        if let Some(code) = build.experimental_result {
            b = b.avp(experimental_result(code));
        }
        let json = ctx.response_json();
        for spec in &build.avps {
            if let Some(rendered) = self.render_avp(rule_id, spec, ctx, json.as_ref())? {
                b = b.avp(rendered);
            }
        }
        Ok(b.build())
    }

    /// Render one answer AVP. `Ok(None)` means the (optional) source was
    /// absent and the AVP is skipped; a missing `required` source fails the
    /// transaction instead of emitting a structurally wrong answer.
    fn render_avp(
        &self,
        rule_id: &str,
        spec: &AvpSpec,
        ctx: &TranslationContext,
        json: Option<&serde_json::Value>,
    ) -> Result<Option<Avp>, CoreError> {
        // Name validity is guaranteed by RuleSet::validate; defend anyway.
        let def = self.catalog.get(&spec.avp).ok_or_else(|| {
            CoreError::UnableToComply(format!("rule {rule_id}: unknown AVP {}", spec.avp))
        })?;
        let err =
            |msg: String| CoreError::Adapter(format!("rule {rule_id}, avp {}: {msg}", spec.avp));
        let value = match &spec.source {
            AvpSource::Value(template) => {
                Some(encode_scalar(def.kind, substitute(template, &ctx.vars)?).map_err(err)?)
            }
            AvpSource::FromJson { pointer, decode } => json
                .and_then(|j| j.pointer(pointer))
                .filter(|v| !v.is_null())
                .map(|v| encode_json(def.kind, v, *decode))
                .transpose()
                .map_err(err)?,
            AvpSource::FromBody => ctx
                .response
                .as_ref()
                .filter(|r| !r.body.is_empty())
                .map(|r| AvpValue::Octets(r.body.clone())),
            AvpSource::Concat(parts) => concat_parts(parts, ctx, json).map_err(err)?,
            AvpSource::Group(children) => {
                let mut members = Vec::with_capacity(children.len());
                for child in children {
                    if let Some(m) = self.render_avp(rule_id, child, ctx, json)? {
                        members.push(m);
                    }
                }
                // A group whose members all turned out missing is itself
                // treated as missing rather than emitted empty.
                (!members.is_empty()).then_some(AvpValue::Grouped(members))
            }
        };
        match value {
            Some(v) => Ok(Some(match def.vendor {
                Some(vendor) => avp_vendor(def.code, vendor, v),
                None => avp(def.code, v),
            })),
            None if spec.required => Err(CoreError::UnableToComply(format!(
                "rule {rule_id}: required answer AVP {} has no source value",
                spec.avp
            ))),
            None => Ok(None),
        }
    }
}

/// Encode a string value per the AVP's catalog type. Integer kinds parse
/// the decimal string (the inverse of how `extract` renders them).
fn encode_scalar(kind: AvpKind, s: String) -> Result<AvpValue, String> {
    Ok(match kind {
        AvpKind::Utf8String => AvpValue::Utf8(s),
        AvpKind::OctetString => AvpValue::Octets(Bytes::from(s.into_bytes())),
        AvpKind::Unsigned32 => AvpValue::U32(s.parse().map_err(|e| format!("not a u32: {e}"))?),
        AvpKind::Unsigned64 => AvpValue::U64(s.parse().map_err(|e| format!("not a u64: {e}"))?),
        AvpKind::Enumerated => AvpValue::Enum(s.parse().map_err(|e| format!("not an i32: {e}"))?),
        // Unreachable for validated rules (group ⇔ Grouped); defend anyway.
        AvpKind::Grouped => return Err("Grouped AVPs need `group:`".to_owned()),
    })
}

/// Encode a JSON value per the AVP's catalog type. `decode: hex` turns a
/// hex string into octets (auth vectors); scalars encode via their string
/// form; sub-objects/arrays embed as compact JSON text where the type is
/// string-like (e.g. Sh `User-Data` carrying a JSON fragment).
fn encode_json(
    kind: AvpKind,
    value: &serde_json::Value,
    decode: Option<Decode>,
) -> Result<AvpValue, String> {
    if decode == Some(Decode::Hex) {
        let s = value.as_str().ok_or("decode: hex needs a JSON string")?;
        return Ok(AvpValue::Octets(crate::mapping::hex_decode(s)?));
    }
    match value {
        serde_json::Value::String(s) => encode_scalar(kind, s.clone()),
        serde_json::Value::Number(n) => encode_scalar(kind, n.to_string()),
        serde_json::Value::Bool(v) => encode_scalar(kind, v.to_string()),
        other => match kind {
            AvpKind::Utf8String => Ok(AvpValue::Utf8(other.to_string())),
            AvpKind::OctetString => Ok(AvpValue::Octets(Bytes::from(other.to_string()))),
            _ => Err(format!("JSON value {other} cannot encode as {kind:?}")),
        },
    }
}

/// Concatenate `concat:` parts into octets. Any missing JSON part makes the
/// whole AVP count as missing (`Ok(None)`), so a partial RAND without its
/// AUTN can never be emitted.
fn concat_parts(
    parts: &[ConcatPart],
    ctx: &TranslationContext,
    json: Option<&serde_json::Value>,
) -> Result<Option<AvpValue>, String> {
    let mut out = Vec::new();
    for part in parts {
        let raw = match &part.source {
            PartSource::Json(pointer) => {
                match json
                    .and_then(|j| j.pointer(pointer))
                    .filter(|v| !v.is_null())
                {
                    Some(serde_json::Value::String(s)) => s.clone(),
                    Some(other) => other.to_string(),
                    None => return Ok(None),
                }
            }
            PartSource::Value(template) => {
                substitute(template, &ctx.vars).map_err(|e| e.to_string())?
            }
        };
        match part.decode {
            Some(Decode::Hex) => out.extend_from_slice(&crate::mapping::hex_decode(&raw)?),
            None => out.extend_from_slice(raw.as_bytes()),
        }
    }
    Ok(Some(AvpValue::Octets(Bytes::from(out))))
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

    // ---- Nhss (TS 29.562) integration tests -----------------------------
    // Drive the *shipped* rules-nhss.yaml through the engine against a mock
    // SbaPort, asserting the correct Nhss path/method/operation and answer.

    const NHSS_RULES: &str = include_str!("../../config/rules-nhss.yaml");

    fn nhss_engine(status: u16, body: serde_json::Value) -> (TranslationEngine, Arc<MockSba>) {
        let sba = Arc::new(MockSba {
            status,
            body,
            seen: Mutex::new(Vec::new()),
        });
        let store = Arc::new(RuleStore::new(
            crate::rule::RuleSet::from_yaml(NHSS_RULES).expect("nhss rules parse"),
        ));
        let engine = TranslationEngine::new(
            store,
            PluginRegistry::with_builtins(),
            sba.clone(),
            "iwf.epc.example.org",
            "epc.example.org",
        );
        (engine, sba)
    }

    #[test]
    fn nhss_rules_validate() {
        // The shipped rule document must parse + validate (set_var, etc.).
        crate::rule::RuleSet::from_yaml(NHSS_RULES).expect("rules-nhss.yaml valid");
    }

    #[tokio::test]
    async fn sar_registration_picks_uecm_registration() {
        let (engine, sba) = nhss_engine(200, serde_json::json!({"imsUserProfile": {}}));
        let sar = MessageBuilder::request(dict::CMD_SAR, dict::APP_CX)
            .ids(1, 1)
            .tgpp(
                dict::AVP_PUBLIC_IDENTITY,
                AvpValue::Utf8("sip:alice@ims.example.org".to_owned()),
            )
            .tgpp(
                dict::AVP_SERVER_ASSIGNMENT_TYPE,
                AvpValue::Enum(dict::server_assignment_type::REGISTRATION),
            )
            .build();
        let answer = engine.translate(&sar, "c").await.expect("answer");
        assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));
        let seen = sba.seen.lock().expect("lock");
        // First call is the UECM op (PUT .../registration), second is SDM_Get.
        assert_eq!(
            seen[0].path,
            "/nhss-ims-uecm/v1/sip:alice@ims.example.org/registration"
        );
        assert_eq!(
            seen[1].path,
            "/nhss-ims-sdm/v1/sip:alice@ims.example.org/ims-data/profile-data"
        );
    }

    #[tokio::test]
    async fn sar_user_deregistration_picks_deregistration() {
        let (engine, sba) = nhss_engine(200, serde_json::json!({}));
        let sar = MessageBuilder::request(dict::CMD_SAR, dict::APP_CX)
            .ids(2, 2)
            .tgpp(
                dict::AVP_PUBLIC_IDENTITY,
                AvpValue::Utf8("sip:bob@ims.example.org".to_owned()),
            )
            .tgpp(
                dict::AVP_SERVER_ASSIGNMENT_TYPE,
                AvpValue::Enum(dict::server_assignment_type::USER_DEREGISTRATION),
            )
            .build();
        engine.translate(&sar, "c").await.expect("answer");
        let seen = sba.seen.lock().expect("lock");
        assert!(
            seen[0].path.ends_with("/deregistration"),
            "got {}",
            seen[0].path
        );
    }

    #[tokio::test]
    async fn sar_no_sat_defaults_to_update() {
        let (engine, sba) = nhss_engine(200, serde_json::json!({}));
        let sar = MessageBuilder::request(dict::CMD_SAR, dict::APP_CX)
            .ids(3, 3)
            .tgpp(
                dict::AVP_PUBLIC_IDENTITY,
                AvpValue::Utf8("sip:c@ims.example.org".to_owned()),
            )
            .build(); // no Server-Assignment-Type
        engine.translate(&sar, "c").await.expect("answer");
        let seen = sba.seen.lock().expect("lock");
        assert!(seen[0].path.ends_with("/update"), "got {}", seen[0].path);
    }

    #[tokio::test]
    async fn udr_data_reference_selects_sdm_resource() {
        let (engine, sba) = nhss_engine(200, serde_json::json!({"serverName": "x"}));
        let udr = MessageBuilder::request(dict::CMD_UDR, dict::APP_SH)
            .ids(4, 4)
            .std(
                dict::AVP_USER_NAME,
                AvpValue::Utf8("alice@ims.example.org".to_owned()),
            )
            .tgpp(
                dict::AVP_DATA_REFERENCE,
                AvpValue::Enum(dict::data_reference::SCSCF_NAME), // 12
            )
            .build();
        let answer = engine.translate(&udr, "c").await.expect("answer");
        assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));
        let seen = sba.seen.lock().expect("lock");
        assert_eq!(seen[0].nf_type, iwf_core::nf::NfType::Hss);
        assert_eq!(
            seen[0].path,
            "/nhss-ims-sdm/v1/alice@ims.example.org/ims-data/location-data/server-name"
        );
    }

    #[tokio::test]
    async fn mar_routes_to_ueau_and_builds_maa() {
        let (engine, sba) = nhss_engine(
            200,
            serde_json::json!({"av5gAka": {"rand":"a5".repeat(16),"autn":"5a".repeat(16),"xresStar":"42".repeat(16)}}),
        );
        let mar = MessageBuilder::request(dict::CMD_MAR, dict::APP_CX)
            .ids(5, 5)
            .std(
                dict::AVP_USER_NAME,
                AvpValue::Utf8("alice@ims.example.org".to_owned()),
            )
            .build();
        let answer = engine.translate(&mar, "c").await.expect("answer");
        assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));
        let seen = sba.seen.lock().expect("lock");
        assert!(seen[0].path.starts_with("/nhss-ims-ueau/v1/"));
        // The declarative spec assembled the binary vector: RAND‖AUTN from
        // two hex-decoded concat parts, XRES* hex-decoded.
        let item = answer
            .find(dict::AVP_SIP_AUTH_DATA_ITEM, Some(dict::VENDOR_3GPP))
            .expect("SIP-Auth-Data-Item")
            .as_grouped()
            .expect("grouped");
        let payload = |code: u32| {
            item.iter()
                .find(|a| a.code == code)
                .map(|a| a.data.clone())
                .expect("member AVP")
        };
        assert_eq!(payload(dict::AVP_SIP_AUTHENTICATE).len(), 32, "RAND||AUTN");
        assert_eq!(payload(dict::AVP_SIP_AUTHENTICATE)[0], 0xA5);
        assert_eq!(payload(dict::AVP_SIP_AUTHORIZATION).as_ref(), &[0x42; 16]);
        // Optional CK'/IK' absent from the response → skipped, not emitted.
        assert!(!item.iter().any(|a| a.code == dict::AVP_CONFIDENTIALITY_KEY));
    }

    #[tokio::test]
    async fn new_interface_ships_as_yaml_only() {
        // The dynamic-mapping guarantee: a made-up vendor interface defined
        // entirely in configuration — dictionary entries plus a rule with a
        // declarative answer — translates end-to-end with zero Rust changes.
        let catalog = Arc::new(
            crate::catalog::AvpCatalog::from_yaml(
                r#"
interfaces:
  foo:
    application: 16777299
    avps:
      - { name: Foo-Token, code: 9001, vendor: 4242, type: UTF8String }
      - { name: Foo-Count, code: 9002, vendor: 4242, type: Unsigned32 }
"#,
            )
            .expect("catalog"),
        );
        let rules = r#"
rules:
  - id: foo_cmd
    trigger: { diameter_application: 16777299, command_code: 999 }
    actions:
      - extract: { avp: "Foo-Token", as: tok }
      - http_request: { method: GET, nf_type: HSS, path: "/foo/v1/{tok}" }
      - map_response:
          200:
            result_code: 2001
            avps:
              - { avp: Foo-Token, value: "{tok}" }
              - { avp: Foo-Count, from_json: "/count", required: true }
          default: { result_code: 5012 }
    version: v1
"#;
        let sba = Arc::new(MockSba {
            status: 200,
            body: serde_json::json!({"count": 7}),
            seen: Mutex::new(Vec::new()),
        });
        let store = Arc::new(RuleStore::with_catalog(
            crate::rule::RuleSet::from_yaml_with(rules, &catalog).expect("rules"),
            catalog.clone(),
        ));
        let engine = TranslationEngine::new(
            store,
            PluginRegistry::with_builtins(),
            sba.clone(),
            "iwf.example.org",
            "example.org",
        )
        .with_catalog(catalog);

        let req = MessageBuilder::request(999, 16_777_299)
            .ids(7, 7)
            .avp(iwf_diameter::avp::avp_vendor(
                9001,
                4242,
                AvpValue::Utf8("tok-1".to_owned()),
            ))
            .build();
        let answer = engine.translate(&req, "c").await.expect("answer");
        assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));
        assert_eq!(sba.seen.lock().expect("lock")[0].path, "/foo/v1/tok-1");
        assert_eq!(
            answer.find(9001, Some(4242)).and_then(|a| a.as_utf8().ok()),
            Some("tok-1"),
            "extracted var echoed via `value` template"
        );
        assert_eq!(
            answer.find(9002, Some(4242)).and_then(|a| a.as_u32().ok()),
            Some(7),
            "JSON number encoded per the dictionary's Unsigned32"
        );
    }

    #[tokio::test]
    async fn lir_builds_lia_with_server_name() {
        let (engine, _) = nhss_engine(
            200,
            serde_json::json!({"serverName": "sip:scscf1.ims.example.org"}),
        );
        let lir = MessageBuilder::request(dict::CMD_LIR, dict::APP_CX)
            .ids(6, 6)
            .tgpp(
                dict::AVP_PUBLIC_IDENTITY,
                AvpValue::Utf8("sip:alice@ims.example.org".to_owned()),
            )
            .build();
        let answer = engine.translate(&lir, "c").await.expect("answer");
        assert_eq!(answer.result_code(), Some(dict::RC_SUCCESS));
        assert_eq!(
            answer
                .find(dict::AVP_SERVER_NAME, Some(dict::VENDOR_3GPP))
                .and_then(|a| a.as_utf8().ok()),
            Some("sip:scscf1.ims.example.org")
        );
    }
}
