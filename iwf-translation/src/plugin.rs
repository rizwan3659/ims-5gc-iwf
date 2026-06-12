//! Plugin surface: rules name an *answer builder*; builders are
//! [`TranslationPlugin`] trait objects looked up in a [`PluginRegistry`].
//! Operators extend the IWF by registering additional plugins from their own
//! crate — no engine changes required.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;

use iwf_core::error::CoreError;
use iwf_core::ports::SbiResponse;
use iwf_diameter::avp::{avp, avp_3gpp, AvpValue};
use iwf_diameter::dictionary as dict;
use iwf_diameter::message::{Message, MessageBuilder};

/// Everything a builder may need to construct the Diameter answer.
#[derive(Debug, Clone)]
pub struct TranslationContext {
    /// The original Diameter request (AVPs are zero-copy handles; cloning
    /// the message is cheap).
    pub request: Message,
    /// Variables extracted by `extract` actions.
    pub vars: BTreeMap<String, String>,
    /// Response of the last `http_request` action, if any was executed.
    pub response: Option<SbiResponse>,
    /// Local Origin-Host for answer AVPs.
    pub origin_host: String,
    /// Local Origin-Realm for answer AVPs.
    pub origin_realm: String,
}

impl TranslationContext {
    /// Begin a spec-compliant answer: correlation ids copied, Session-Id
    /// mirrored (RFC 6733 §8.8), Origin-Host/Realm set (§6.2).
    pub fn answer(&self) -> MessageBuilder {
        let mut b = MessageBuilder::answer_to(&self.request.header);
        if let Some(sid) = self.request.session_id() {
            b = b.std(dict::AVP_SESSION_ID, AvpValue::Utf8(sid.to_owned()));
        }
        b.std(
            dict::AVP_ORIGIN_HOST,
            AvpValue::Utf8(self.origin_host.clone()),
        )
        .std(
            dict::AVP_ORIGIN_REALM,
            AvpValue::Utf8(self.origin_realm.clone()),
        )
    }

    /// Parse the JSON body of the captured response, if any.
    pub fn response_json(&self) -> Option<serde_json::Value> {
        let r = self.response.as_ref()?;
        serde_json::from_slice(&r.body).ok()
    }
}

/// An answer builder addressable from `map_response`.
pub trait TranslationPlugin: Send + Sync {
    /// Registry key used in rule documents.
    fn name(&self) -> &'static str;
    /// Build the Diameter answer for `ctx`.
    fn build_answer(&self, ctx: &TranslationContext) -> Result<Message, CoreError>;
}

/// Grouped `Experimental-Result` carrying a 3GPP experimental code
/// (TS 29.229 §6.2: Vendor-Id 10415 + Experimental-Result-Code).
fn experimental_result(code: u32) -> iwf_diameter::avp::Avp {
    avp(
        dict::AVP_EXPERIMENTAL_RESULT,
        AvpValue::Grouped(vec![
            avp(dict::AVP_VENDOR_ID, AvpValue::U32(dict::VENDOR_3GPP)),
            avp(dict::AVP_EXPERIMENTAL_RESULT_CODE, AvpValue::U32(code)),
        ]),
    )
}

macro_rules! simple_plugin {
    ($(#[$doc:meta])* $ty:ident, $name:literal, |$ctx:ident| $body:expr) => {
        $(#[$doc])*
        pub struct $ty;

        impl TranslationPlugin for $ty {
            fn name(&self) -> &'static str {
                $name
            }
            fn build_answer(&self, $ctx: &TranslationContext) -> Result<Message, CoreError> {
                $body
            }
        }
    };
}

simple_plugin!(
    /// UAA success: `Result-Code` 2001 plus `Server-Name` when the UDM
    /// registration response names a serving S-CSCF (TS 29.229 §6.1.2,
    /// TS 29.503 §6.3 ImsRegistration).
    BuildUaaSuccess,
    "build_uaa_success",
    |ctx| {
        let mut b = ctx
            .answer()
            .std(dict::AVP_RESULT_CODE, AvpValue::U32(dict::RC_SUCCESS));
        if let Some(json) = ctx.response_json() {
            if let Some(scscf) = json
                .get("scscfName")
                .or_else(|| json.get("serverName"))
                .and_then(serde_json::Value::as_str)
            {
                b = b.tgpp(dict::AVP_SERVER_NAME, AvpValue::Utf8(scscf.to_owned()));
            }
        }
        Ok(b.build())
    }
);

simple_plugin!(
    /// UAA user-unknown: `Experimental-Result-Code` 5001
    /// DIAMETER_ERROR_USER_UNKNOWN (TS 29.229 §6.2.2.1), mapped from
    /// HTTP 404 per TS 29.500 §5.2.7.
    BuildUaaUserUnknown,
    "build_uaa_user_unknown",
    |ctx| Ok(ctx.answer().avp(experimental_result(dict::ERC_USER_UNKNOWN)).build())
);

simple_plugin!(
    /// UAA unable-to-comply: `Result-Code` 5012 (RFC 6733 §7.1.5), mapped
    /// from HTTP 5xx per TS 29.500 §5.2.7.
    BuildUaaUnableToComply,
    "build_uaa_unable_to_comply",
    |ctx| {
        Ok(ctx
            .answer()
            .std(
                dict::AVP_RESULT_CODE,
                AvpValue::U32(dict::RC_UNABLE_TO_COMPLY),
            )
            .build())
    }
);

simple_plugin!(
    /// Generic success answer (SAA/LIA/RTA/UDA/PUA when no body mapping is
    /// needed beyond Result-Code 2001).
    BuildSuccess,
    "build_success",
    |ctx| {
        Ok(ctx
            .answer()
            .std(dict::AVP_RESULT_CODE, AvpValue::U32(dict::RC_SUCCESS))
            .build())
    }
);

simple_plugin!(
    /// Generic user-unknown (Experimental 5001) for any Cx/Sh answer.
    BuildUserUnknown,
    "build_user_unknown",
    |ctx| Ok(ctx.answer().avp(experimental_result(dict::ERC_USER_UNKNOWN)).build())
);

simple_plugin!(
    /// Generic unable-to-comply (5012) for any Cx/Sh answer.
    BuildUnableToComply,
    "build_unable_to_comply",
    |ctx| {
        Ok(ctx
            .answer()
            .std(
                dict::AVP_RESULT_CODE,
                AvpValue::U32(dict::RC_UNABLE_TO_COMPLY),
            )
            .build())
    }
);

simple_plugin!(
    /// Sh UDA success: `Result-Code` 2001 with the repository payload echoed
    /// in `User-Data` (TS 29.329 §6.1.2; body sourced from
    /// `/nudr-dr/v1/subscription-data` per TS 29.504 §5.2.2).
    BuildUdaSuccess,
    "build_uda_success",
    |ctx| {
        let mut b = ctx
            .answer()
            .std(dict::AVP_RESULT_CODE, AvpValue::U32(dict::RC_SUCCESS));
        if let Some(r) = &ctx.response {
            if !r.body.is_empty() {
                b = b.tgpp(dict::AVP_USER_DATA, AvpValue::Octets(r.body.clone()));
            }
        }
        Ok(b.build())
    }
);

/// MAA success: Result-Code 2001 plus a `SIP-Auth-Data-Item` group built
/// from the AUSF `Av5gAka` (TS 29.229 §6.3.13 ← TS 29.509 §6.1.6.3.4):
/// `SIP-Authenticate` = RAND‖AUTN, `SIP-Authorization` = XRES*,
/// `Confidentiality-Key`/`Integrity-Key` when CK'/IK' are present.
pub struct BuildMaaSuccess;

impl TranslationPlugin for BuildMaaSuccess {
    fn name(&self) -> &'static str {
        "build_maa_success"
    }

    fn build_answer(&self, ctx: &TranslationContext) -> Result<Message, CoreError> {
        let json = ctx
            .response_json()
            .ok_or(CoreError::MissingElement("AUSF response body"))?;
        let av = json
            .pointer("/5gAuthData")
            .or_else(|| json.get("av5gAka"))
            .ok_or(CoreError::MissingElement("Av5gAka in AUSF response"))?;
        let auth = crate::mapping::auth_from_av5g_aka(av)?;

        let mut group = vec![
            avp_3gpp(
                dict::AVP_SIP_AUTH_SCHEME,
                AvpValue::Utf8("Digest-AKAv1-MD5".to_owned()),
            ),
            avp_3gpp(
                dict::AVP_SIP_AUTHENTICATE,
                AvpValue::Octets(auth.sip_authenticate()),
            ),
            avp_3gpp(
                dict::AVP_SIP_AUTHORIZATION,
                AvpValue::Octets(auth.xres_star.clone()),
            ),
        ];
        if let Some(ck) = &auth.ck_prime {
            group.push(avp_3gpp(
                dict::AVP_CONFIDENTIALITY_KEY,
                AvpValue::Octets(ck.clone()),
            ));
        }
        if let Some(ik) = &auth.ik_prime {
            group.push(avp_3gpp(
                dict::AVP_INTEGRITY_KEY,
                AvpValue::Octets(ik.clone()),
            ));
        }

        Ok(ctx
            .answer()
            .std(dict::AVP_RESULT_CODE, AvpValue::U32(dict::RC_SUCCESS))
            .tgpp(dict::AVP_SIP_NUMBER_AUTH_ITEMS, AvpValue::U32(1))
            .tgpp(dict::AVP_SIP_AUTH_DATA_ITEM, AvpValue::Grouped(group))
            .build())
    }
}

/// Name → plugin lookup. Cloning is cheap (`Arc`s).
#[derive(Clone, Default)]
pub struct PluginRegistry {
    plugins: HashMap<&'static str, Arc<dyn TranslationPlugin>>,
}

impl std::fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginRegistry")
            .field("plugins", &self.plugins.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl PluginRegistry {
    /// Registry pre-loaded with every built-in builder.
    pub fn with_builtins() -> Self {
        let mut r = PluginRegistry::default();
        r.register(Arc::new(BuildUaaSuccess));
        r.register(Arc::new(BuildUaaUserUnknown));
        r.register(Arc::new(BuildUaaUnableToComply));
        r.register(Arc::new(BuildSuccess));
        r.register(Arc::new(BuildUserUnknown));
        r.register(Arc::new(BuildUnableToComply));
        r.register(Arc::new(BuildUdaSuccess));
        r.register(Arc::new(BuildMaaSuccess));
        r
    }

    /// Register (or replace) a plugin under its own name.
    pub fn register(&mut self, plugin: Arc<dyn TranslationPlugin>) {
        self.plugins.insert(plugin.name(), plugin);
    }

    /// Look a builder up by rule-document name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn TranslationPlugin>> {
        self.plugins.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn ctx_with(status: u16, body: serde_json::Value) -> TranslationContext {
        let request = MessageBuilder::request(dict::CMD_UAR, dict::APP_CX)
            .ids(1, 2)
            .std(dict::AVP_SESSION_ID, AvpValue::Utf8("iwf;1;1".to_owned()))
            .build();
        TranslationContext {
            request,
            vars: BTreeMap::new(),
            response: Some(SbiResponse {
                status,
                body: Bytes::from(body.to_string()),
            }),
            origin_host: "iwf.example.org".to_owned(),
            origin_realm: "example.org".to_owned(),
        }
    }

    #[test]
    fn uaa_success_carries_server_name() {
        let ctx = ctx_with(
            200,
            serde_json::json!({"scscfName": "sip:scscf1.example.org"}),
        );
        let ans = BuildUaaSuccess.build_answer(&ctx).expect("build");
        assert_eq!(ans.result_code(), Some(dict::RC_SUCCESS));
        assert_eq!(
            ans.find(dict::AVP_SERVER_NAME, Some(dict::VENDOR_3GPP))
                .and_then(|a| a.as_utf8().ok()),
            Some("sip:scscf1.example.org")
        );
        assert_eq!(ans.session_id(), Some("iwf;1;1"));
    }

    #[test]
    fn user_unknown_uses_experimental_result() {
        let ctx = ctx_with(404, serde_json::json!({}));
        let ans = BuildUaaUserUnknown.build_answer(&ctx).expect("build");
        assert_eq!(ans.result_code(), None, "no plain Result-Code");
        let group = ans
            .find(dict::AVP_EXPERIMENTAL_RESULT, None)
            .expect("Experimental-Result")
            .as_grouped()
            .expect("grouped");
        let code = group
            .iter()
            .find(|a| a.code == dict::AVP_EXPERIMENTAL_RESULT_CODE)
            .expect("code AVP")
            .as_u32()
            .expect("u32");
        assert_eq!(code, dict::ERC_USER_UNKNOWN);
    }

    #[test]
    fn maa_success_builds_auth_data_item() {
        let ctx = ctx_with(
            200,
            serde_json::json!({
                "av5gAka": {
                    "rand": "a5".repeat(16),
                    "autn": "5a".repeat(16),
                    "xresStar": "42".repeat(16),
                }
            }),
        );
        let ans = BuildMaaSuccess.build_answer(&ctx).expect("build");
        let item = ans
            .find(dict::AVP_SIP_AUTH_DATA_ITEM, Some(dict::VENDOR_3GPP))
            .expect("auth data item");
        let members = item.as_grouped().expect("grouped");
        let authenticate = members
            .iter()
            .find(|a| a.code == dict::AVP_SIP_AUTHENTICATE)
            .expect("SIP-Authenticate");
        assert_eq!(authenticate.data.len(), 32, "RAND||AUTN");
    }

    #[test]
    fn registry_resolves_builtins() {
        let r = PluginRegistry::with_builtins();
        for name in [
            "build_uaa_success",
            "build_uaa_user_unknown",
            "build_uaa_unable_to_comply",
            "build_maa_success",
            "build_uda_success",
        ] {
            assert!(r.get(name).is_some(), "{name} not registered");
        }
        assert!(r.get("nope").is_none());
    }
}
