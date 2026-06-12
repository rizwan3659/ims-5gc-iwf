//! Authentication material exchanged between IMS (Cx MAR/MAA, TS 29.228/229)
//! and 5GC (Nausf_UEAuthentication, TS 29.509; key hierarchy TS 33.501 §6.1).

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// Authentication scheme negotiated on the Cx interface
/// (`SIP-Authentication-Scheme` AVP, TS 29.229 §6.3.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthScheme {
    /// IMS-AKA per TS 33.203, mapped onto 5G AKA vectors from AUSF.
    DigestAkaV1Md5,
    /// EAP-AKA' (TS 33.501 Annex F), used on SWx-style flows.
    EapAkaPrime,
    /// SIP Digest (TS 29.228 Annex), no AKA vector involved.
    SipDigest,
}

impl AuthScheme {
    /// Wire form used in the `SIP-Authentication-Scheme` AVP.
    pub fn as_avp_str(&self) -> &'static str {
        match self {
            AuthScheme::DigestAkaV1Md5 => "Digest-AKAv1-MD5",
            AuthScheme::EapAkaPrime => "EAP-AKA'",
            AuthScheme::SipDigest => "SIP Digest",
        }
    }

    /// Parse the wire form; unknown schemes are rejected so that rules can
    /// explicitly opt in to every scheme they translate.
    pub fn from_avp_str(s: &str) -> Result<Self, CoreError> {
        match s {
            "Digest-AKAv1-MD5" => Ok(AuthScheme::DigestAkaV1Md5),
            "EAP-AKA'" => Ok(AuthScheme::EapAkaPrime),
            "SIP Digest" => Ok(AuthScheme::SipDigest),
            _ => Err(CoreError::MissingElement("known SIP-Authentication-Scheme")),
        }
    }
}

/// One authentication vector in flight through the IWF.
///
/// Field provenance:
/// - `rand`, `autn`: TS 33.501 §6.1.3 (5G AKA challenge), carried on Cx in
///   `SIP-Authenticate` (TS 29.229 §6.3.10: RAND ‖ AUTN).
/// - `xres_star`: XRES* per TS 33.501 A.4 — the 5G AKA expected response.
/// - `xres`: EPS/IMS AKA XRES when the AUSF/HSS supplied a non-5G vector
///   (fallback for legacy IMS clients).
/// - `ck_prime`/`ik_prime`: CK'/IK' per TS 33.501 Annex A.8 for EAP-AKA';
///   for IMS-AKA the (CK, IK) pair is carried in `Confidentiality-Key` /
///   `Integrity-Key` AVPs (TS 29.229 §6.3.27/6.3.28).
///
/// All fields are `bytes::Bytes` so vectors can be sliced out of decoded
/// messages without copying. `Debug` is intentionally redacted: key material
/// must never reach logs (see `iwf-observability` PII policy).
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// 16-octet random challenge.
    pub rand: Bytes,
    /// 16-octet authentication token.
    pub autn: Bytes,
    /// 5G AKA expected response XRES* (16 octets).
    pub xres_star: Bytes,
    /// EPS/IMS AKA expected response, when a legacy vector is in play.
    pub xres: Option<Bytes>,
    /// CK' for EAP-AKA' (or CK for IMS-AKA flows).
    pub ck_prime: Option<Bytes>,
    /// IK' for EAP-AKA' (or IK for IMS-AKA flows).
    pub ik_prime: Option<Bytes>,
}

impl AuthContext {
    /// Validate octet lengths per TS 33.501 §6.1.3 (RAND/AUTN are 16 octets;
    /// XRES* is 16 octets).
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.rand.len() != 16 {
            return Err(CoreError::MissingElement("16-octet RAND"));
        }
        if self.autn.len() != 16 {
            return Err(CoreError::MissingElement("16-octet AUTN"));
        }
        if self.xres_star.len() != 16 {
            return Err(CoreError::MissingElement("16-octet XRES*"));
        }
        Ok(())
    }

    /// `SIP-Authenticate` payload per TS 29.229 §6.3.10: RAND ‖ AUTN.
    pub fn sip_authenticate(&self) -> Bytes {
        let mut buf = Vec::with_capacity(self.rand.len() + self.autn.len());
        buf.extend_from_slice(&self.rand);
        buf.extend_from_slice(&self.autn);
        Bytes::from(buf)
    }
}

impl std::fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material is never printed; only presence/length is observable.
        f.debug_struct("AuthContext")
            .field("rand_len", &self.rand.len())
            .field("autn_len", &self.autn.len())
            .field("xres_star_len", &self.xres_star.len())
            .field("xres", &self.xres.as_ref().map(Bytes::len))
            .field("ck_prime", &self.ck_prime.as_ref().map(Bytes::len))
            .field("ik_prime", &self.ik_prime.as_ref().map(Bytes::len))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector() -> AuthContext {
        AuthContext {
            rand: Bytes::from_static(&[0xA5; 16]),
            autn: Bytes::from_static(&[0x5A; 16]),
            xres_star: Bytes::from_static(&[0x42; 16]),
            xres: None,
            ck_prime: None,
            ik_prime: None,
        }
    }

    #[test]
    fn validate_enforces_octet_lengths() {
        assert!(vector().validate().is_ok());
        let mut bad = vector();
        bad.rand = Bytes::from_static(&[0u8; 8]);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn sip_authenticate_is_rand_concat_autn() {
        let v = vector();
        let payload = v.sip_authenticate();
        assert_eq!(payload.len(), 32);
        assert_eq!(&payload[..16], &[0xA5; 16]);
        assert_eq!(&payload[16..], &[0x5A; 16]);
    }

    #[test]
    fn debug_redacts_key_material() {
        let printed = format!("{:?}", vector());
        assert!(!printed.contains("A5"));
        assert!(printed.contains("rand_len"));
    }

    #[test]
    fn scheme_round_trip() {
        for s in [
            AuthScheme::DigestAkaV1Md5,
            AuthScheme::EapAkaPrime,
            AuthScheme::SipDigest,
        ] {
            assert_eq!(
                AuthScheme::from_avp_str(s.as_avp_str()).expect("round trip"),
                s
            );
        }
        assert!(AuthScheme::from_avp_str("Digest-MD5-bogus").is_err());
    }
}
