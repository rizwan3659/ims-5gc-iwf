//! Bidirectional data mapping between Diameter AVPs and SBA JSON fields.
//!
//! Every mapping in this module cites the clause that mandates it. The
//! master cross-reference:
//!
//! | Diameter AVP (source)                  | SBA JSON field (target)                  | Mandating clauses |
//! |----------------------------------------|------------------------------------------|-------------------|
//! | `User-Name` (RFC 6733 §8.14; IMPI per TS 29.229 §6.3.1) | `{impi}` path segment of `/nudm-uecm/v1/{ueId}/registrations` | TS 29.503 §5.3.2 (`ueId` accepts IMPI for IMS), TS 23.003 §13.3 |
//! | `Public-Identity` (TS 29.229 §6.3.2)   | `impu` query / `PublicIdentities.publicIdentities` | TS 29.503 §6.3.6.2.2 |
//! | `User-Name` → SUPI                     | `supi` (`imsi-…`)                        | TS 23.003 §13.3 (IMPI username = IMSI), TS 29.571 §5.3.2 |
//! | `SIP-Auth-Data-Item/SIP-Authentication-Scheme` (TS 29.229 §6.3.9) | `AuthenticationInfoRequest.authType` | TS 29.509 §6.1.6.2.2 |
//! | `SIP-Authenticate` = RAND‖AUTN (TS 29.229 §6.3.10) | `Av5gAka.rand` + `.autn` (hex)  | TS 29.509 §6.1.6.3.4, TS 33.501 §6.1.3.2 |
//! | `SIP-Authorization` (XRES, TS 29.229 §6.3.11) | `Av5gAka.xresStar` / EPS `xres`   | TS 29.509 §6.1.6.3.4, TS 33.501 A.4 |
//! | `Confidentiality-Key` (TS 29.229 §6.3.27) | EAP-AKA' `ckPrime`                    | TS 29.509 §6.1.6.3.3, TS 33.501 A.8 |
//! | `Integrity-Key` (TS 29.229 §6.3.28)    | EAP-AKA' `ikPrime`                       | TS 29.509 §6.1.6.3.3 |
//! | `Server-Name` (TS 29.229 §6.3.3)       | `Scscf-Registration.scscfInstanceId` analogue | TS 29.503 §6.3.6.2 (IMS registration data) |
//! | `MSISDN` (TS 29.329 §6.3.2A, BCD)      | `gpsi` = `msisdn-<digits>`               | TS 29.571 §5.3.2, TS 23.003 §28.8 |
//! | `User-Data` (Sh, TS 29.329 §6.3.1)     | `/nudr-dr/v1/subscription-data` resource body | TS 29.504 §5.2.2, TS 29.519 |
//! | `Result-Code`/`Experimental-Result` (RFC 6733 §7.1, TS 29.229 §6.2) | HTTP status + `ProblemDetails.cause` | TS 29.500 §5.2.7 (status mapping table) |

use bytes::Bytes;
use iwf_core::auth::AuthContext;
use iwf_core::error::CoreError;
use iwf_core::identity::{Gpsi, IdentityContext, Impi, Impu, Supi};
use iwf_diameter::dictionary as dict;
use iwf_diameter::message::Message;

/// Resolve a DSL AVP name to `(code, vendor_id)`.
///
/// Names follow the spec spelling (TS 29.229/29.329 tables); the DSL is
/// validated against this registry at load time, so a typo in a rule fails
/// the reload instead of a live transaction.
pub fn avp_by_name(name: &str) -> Option<(u32, Option<u32>)> {
    let v3 = Some(dict::VENDOR_3GPP);
    Some(match name {
        "User-Name" => (dict::AVP_USER_NAME, None),
        "Session-Id" => (dict::AVP_SESSION_ID, None),
        "Origin-Host" => (dict::AVP_ORIGIN_HOST, None),
        "Origin-Realm" => (dict::AVP_ORIGIN_REALM, None),
        "Destination-Realm" => (dict::AVP_DESTINATION_REALM, None),
        "Destination-Host" => (dict::AVP_DESTINATION_HOST, None),
        "Result-Code" => (dict::AVP_RESULT_CODE, None),
        "Public-Identity" => (dict::AVP_PUBLIC_IDENTITY, v3),
        "Server-Name" => (dict::AVP_SERVER_NAME, v3),
        "User-Data" => (dict::AVP_USER_DATA, v3),
        "SIP-Number-Auth-Items" => (dict::AVP_SIP_NUMBER_AUTH_ITEMS, v3),
        "SIP-Authentication-Scheme" => (dict::AVP_SIP_AUTH_SCHEME, v3),
        "SIP-Authenticate" => (dict::AVP_SIP_AUTHENTICATE, v3),
        "SIP-Authorization" => (dict::AVP_SIP_AUTHORIZATION, v3),
        "SIP-Auth-Data-Item" => (dict::AVP_SIP_AUTH_DATA_ITEM, v3),
        "Server-Assignment-Type" => (dict::AVP_SERVER_ASSIGNMENT_TYPE, v3),
        "User-Authorization-Type" => (dict::AVP_USER_AUTHORIZATION_TYPE, v3),
        "Confidentiality-Key" => (dict::AVP_CONFIDENTIALITY_KEY, v3),
        "Integrity-Key" => (dict::AVP_INTEGRITY_KEY, v3),
        "Data-Reference" => (dict::AVP_DATA_REFERENCE, v3),
        "MSISDN" => (dict::AVP_MSISDN, v3),
        "Subs-Req-Type" => (dict::AVP_SUBS_REQ_TYPE, v3),
        _ => return None,
    })
}

/// Build an [`IdentityContext`] from a Cx request.
///
/// - IMPI ← `User-Name` (TS 29.229 §6.3.1 carries the IMPI on UAR/SAR/MAR/LIR).
/// - IMPU ← every `Public-Identity` (TS 29.229 §6.3.2; UAR carries one, SAR
///   may carry several).
/// - SUPI ← derived from IMSI-based IMPI per TS 23.003 §13.3 when possible.
/// - GPSI ← `MSISDN` (Sh, TS 29.329 §6.3.2A) decoded from TBCD.
pub fn identity_from_cx(msg: &Message) -> Result<IdentityContext, CoreError> {
    let mut ctx = IdentityContext::default();

    if let Some(avp) = msg.find(dict::AVP_USER_NAME, None) {
        let raw = avp
            .as_utf8()
            .map_err(|e| CoreError::Adapter(format!("User-Name: {e}")))?;
        ctx.impi = Some(Impi::new(raw)?);
    }
    for avp in msg.find_all(dict::AVP_PUBLIC_IDENTITY, Some(dict::VENDOR_3GPP)) {
        let raw = avp
            .as_utf8()
            .map_err(|e| CoreError::Adapter(format!("Public-Identity: {e}")))?;
        ctx.impu.push(Impu::new(raw)?);
    }
    if let Some(avp) = msg.find(dict::AVP_MSISDN, Some(dict::VENDOR_3GPP)) {
        let digits = tbcd_decode(&avp.as_octets())?;
        ctx.gpsi = Some(Gpsi::new(format!("msisdn-{digits}"))?);
    }
    ctx.supi = ctx.derive_supi_from_impi();
    Ok(ctx)
}

/// Decode TBCD-encoded digits (TS 29.002 §17.7.8 / TS 23.003): two digits
/// per octet, low nibble first, `0xF` pads an odd-length number.
pub fn tbcd_decode(raw: &Bytes) -> Result<String, CoreError> {
    let mut out = String::with_capacity(raw.len() * 2);
    for octet in raw.iter() {
        for nibble in [octet & 0x0F, octet >> 4] {
            match nibble {
                0..=9 => out.push(char::from(b'0' + nibble)),
                0xF => {} // filler
                _ => {
                    return Err(CoreError::Adapter(format!(
                        "invalid TBCD nibble {nibble:#x}"
                    )))
                }
            }
        }
    }
    Ok(out)
}

/// Encode digits as TBCD (inverse of [`tbcd_decode`]).
pub fn tbcd_encode(digits: &str) -> Result<Bytes, CoreError> {
    let bytes = digits.as_bytes();
    if !bytes.iter().all(u8::is_ascii_digit) {
        return Err(CoreError::Adapter("TBCD input must be decimal".to_owned()));
    }
    let mut out = Vec::with_capacity(bytes.len().div_ceil(2));
    for pair in bytes.chunks(2) {
        let low = pair[0] - b'0';
        let high = if pair.len() == 2 { pair[1] - b'0' } else { 0xF };
        out.push((high << 4) | low);
    }
    Ok(Bytes::from(out))
}

/// Parse an `Av5gAka` JSON object (TS 29.509 §6.1.6.3.4) into an
/// [`AuthContext`]. Hex fields per the OpenAPI (`rand`, `autn`, `xresStar`
/// are lower-case hex strings).
pub fn auth_from_av5g_aka(av: &serde_json::Value) -> Result<AuthContext, CoreError> {
    let hex_field = |name: &'static str| -> Result<Bytes, CoreError> {
        let s = av
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or(CoreError::MissingElement(name))?;
        hex_decode(s).map_err(|e| CoreError::Adapter(format!("{name}: {e}")))
    };
    let ctx = AuthContext {
        rand: hex_field("rand")?,
        autn: hex_field("autn")?,
        xres_star: hex_field("xresStar")?,
        xres: None,
        ck_prime: None,
        ik_prime: None,
    };
    ctx.validate()?;
    Ok(ctx)
}

fn hex_decode(s: &str) -> Result<Bytes, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex".to_owned());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16).ok_or("bad hex digit")?;
        let lo = (b[i + 1] as char).to_digit(16).ok_or("bad hex digit")?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(Bytes::from(out))
}

/// Resolve the `{ueId}` to place in Nudm paths (TS 29.503 §5.3.2: SUPI or,
/// for IMS interworking, the IMPI). Preference order: SUPI, then IMPI.
pub fn udm_ue_id(ctx: &IdentityContext) -> Result<String, CoreError> {
    if let Some(supi) = &ctx.supi {
        return Ok(supi.as_str().to_owned());
    }
    if let Some(impi) = &ctx.impi {
        return Ok(impi.as_str().to_owned());
    }
    Err(CoreError::MissingElement("SUPI or IMPI for ueId"))
}

/// Map a SUPI back to the IMPI realm form when answering Cx (TS 23.003
/// §13.3: IMSI-derived IMPI is `<imsi>@ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org`).
/// `home_realm` supplies the operator realm when it cannot be derived.
pub fn impi_from_supi(supi: &Supi, home_realm: &str) -> Result<Impi, CoreError> {
    let user = supi
        .as_str()
        .strip_prefix("imsi-")
        .ok_or(CoreError::MissingElement("imsi-form SUPI"))?;
    Impi::new(format!("{user}@{home_realm}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iwf_diameter::avp::AvpValue;
    use iwf_diameter::message::MessageBuilder;

    #[test]
    fn identity_extraction_from_uar() {
        let msg = MessageBuilder::request(dict::CMD_UAR, dict::APP_CX)
            .std(
                dict::AVP_USER_NAME,
                AvpValue::Utf8("001011234567890@ims.mnc001.mcc001.3gppnetwork.org".to_owned()),
            )
            .tgpp(
                dict::AVP_PUBLIC_IDENTITY,
                AvpValue::Utf8("sip:alice@example.org".to_owned()),
            )
            .build();
        let ctx = identity_from_cx(&msg).expect("extract");
        assert_eq!(
            ctx.supi.as_ref().map(Supi::as_str),
            Some("imsi-001011234567890"),
            "SUPI derived per TS 23.003 §13.3"
        );
        assert_eq!(ctx.impu.len(), 1);
        assert_eq!(udm_ue_id(&ctx).expect("ueId"), "imsi-001011234567890");
    }

    #[test]
    fn tbcd_round_trip() {
        for digits in ["14155550100", "123456", "5"] {
            let encoded = tbcd_encode(digits).expect("encode");
            assert_eq!(tbcd_decode(&encoded).expect("decode"), digits);
        }
        assert!(tbcd_encode("12a").is_err());
    }

    #[test]
    fn av5g_aka_parsing() {
        let av = serde_json::json!({
            "rand": "a5".repeat(16),
            "autn": "5a".repeat(16),
            "xresStar": "42".repeat(16),
        });
        let ctx = auth_from_av5g_aka(&av).expect("parse");
        assert_eq!(ctx.rand.as_ref(), &[0xA5; 16]);
        assert_eq!(ctx.xres_star.as_ref(), &[0x42; 16]);
    }

    #[test]
    fn av5g_aka_rejects_short_rand() {
        let av = serde_json::json!({
            "rand": "a5a5",
            "autn": "5a".repeat(16),
            "xresStar": "42".repeat(16),
        });
        assert!(auth_from_av5g_aka(&av).is_err());
    }

    #[test]
    fn impi_supi_bidirectional() {
        let supi = Supi::new("imsi-001011234567890").expect("supi");
        let impi = impi_from_supi(&supi, "ims.mnc001.mcc001.3gppnetwork.org").expect("impi");
        assert_eq!(
            impi.as_str(),
            "001011234567890@ims.mnc001.mcc001.3gppnetwork.org"
        );
    }

    #[test]
    fn avp_registry_covers_dsl_names() {
        for name in [
            "User-Name",
            "Public-Identity",
            "Server-Name",
            "SIP-Auth-Data-Item",
            "User-Data",
            "MSISDN",
        ] {
            assert!(avp_by_name(name).is_some(), "{name} missing from registry");
        }
        assert!(avp_by_name("Not-An-AVP").is_none());
    }
}
