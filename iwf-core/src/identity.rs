//! Subscriber identity types shared by the IMS (Diameter) and 5GC (SBA) sides.
//!
//! Format rules come from 3GPP TS 23.003:
//! - IMPI: NAI form `user@realm` (§13.3)
//! - IMPU: SIP URI or tel URI (§13.4)
//! - SUPI: `imsi-<5-15 digits>` or `nai-...` (§2.2A, TS 29.571 §5.3.2)
//! - SUCI: `suci-<supi_type>-...` concealed identifier (§2.2B)
//! - GPSI: `msisdn-<digits>` or external identifier (§28.8)

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// Macro-free helper: validate that a string is non-empty and within the
/// 3GPP-practical bound we enforce for identity strings (RFC 6733 caps a
/// UTF8String AVP well above this; 256 octets is the operator-conventional
/// limit for identity AVPs and keeps log lines bounded).
fn check_len(kind: &'static str, s: &str) -> Result<(), CoreError> {
    if s.is_empty() {
        return Err(CoreError::InvalidIdentity {
            kind,
            reason: "empty".to_owned(),
        });
    }
    if s.len() > 256 {
        return Err(CoreError::InvalidIdentity {
            kind,
            reason: format!("length {} exceeds 256 octets", s.len()),
        });
    }
    Ok(())
}

macro_rules! identity_newtype {
    ($(#[$doc:meta])* $name:ident, $kind:literal, $validator:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Parse and validate the raw string form of this identity.
            pub fn new(raw: impl Into<String>) -> Result<Self, CoreError> {
                let raw = raw.into();
                check_len($kind, &raw)?;
                let validator: fn(&str) -> Result<(), CoreError> = $validator;
                validator(&raw)?;
                Ok(Self(raw))
            }

            /// The validated string form.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

identity_newtype!(
    /// IMS Private User Identity (TS 23.003 §13.3): NAI `user@realm`.
    /// Carried in the Diameter `User-Name` AVP (RFC 6733 §8.14, TS 29.229).
    Impi,
    "IMPI",
    |s| {
        if s.contains('@') {
            Ok(())
        } else {
            Err(CoreError::InvalidIdentity {
                kind: "IMPI",
                reason: "must be NAI form user@realm".to_owned(),
            })
        }
    }
);

identity_newtype!(
    /// IMS Public User Identity (TS 23.003 §13.4): `sip:` or `tel:` URI.
    /// Carried in the 3GPP `Public-Identity` AVP (TS 29.229 §6.3.2).
    Impu,
    "IMPU",
    |s| {
        if s.starts_with("sip:") || s.starts_with("sips:") || s.starts_with("tel:") {
            Ok(())
        } else {
            Err(CoreError::InvalidIdentity {
                kind: "IMPU",
                reason: "must be a sip:, sips:, or tel: URI".to_owned(),
            })
        }
    }
);

identity_newtype!(
    /// 5GC Subscription Permanent Identifier (TS 29.571 §5.3.2 `Supi`):
    /// `imsi-<5..15 digits>` or `nai-<NAI>`.
    Supi,
    "SUPI",
    |s| {
        if let Some(digits) = s.strip_prefix("imsi-") {
            let len_ok = (5..=15).contains(&digits.len());
            if len_ok && digits.bytes().all(|b| b.is_ascii_digit()) {
                return Ok(());
            }
            return Err(CoreError::InvalidIdentity {
                kind: "SUPI",
                reason: "imsi- form requires 5..=15 decimal digits".to_owned(),
            });
        }
        if s.starts_with("nai-") {
            return Ok(());
        }
        Err(CoreError::InvalidIdentity {
            kind: "SUPI",
            reason: "must start with imsi- or nai-".to_owned(),
        })
    }
);

identity_newtype!(
    /// 5GC Subscription Concealed Identifier (TS 23.003 §2.2B, TS 29.571).
    /// Opaque to the IWF beyond the scheme prefix; never logged.
    Suci,
    "SUCI",
    |s| {
        if s.starts_with("suci-") {
            Ok(())
        } else {
            Err(CoreError::InvalidIdentity {
                kind: "SUCI",
                reason: "must start with suci-".to_owned(),
            })
        }
    }
);

identity_newtype!(
    /// Generic Public Subscription Identifier (TS 29.571 §5.3.2 `Gpsi`):
    /// `msisdn-<digits>` or `extid-<external identifier>`.
    Gpsi,
    "GPSI",
    |s| {
        if let Some(digits) = s.strip_prefix("msisdn-") {
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                return Ok(());
            }
            return Err(CoreError::InvalidIdentity {
                kind: "GPSI",
                reason: "msisdn- form requires decimal digits".to_owned(),
            });
        }
        if s.starts_with("extid-") {
            return Ok(());
        }
        Err(CoreError::InvalidIdentity {
            kind: "GPSI",
            reason: "must start with msisdn- or extid-".to_owned(),
        })
    }
);

/// The full set of identities known for a subscriber in the scope of one
/// translated transaction.
///
/// IMS-side identities (IMPI/IMPU) and 5GC-side identities (SUPI/SUCI/GPSI)
/// are correlated by the translation engine; mapping rules are documented in
/// `iwf-translation::mapping`. The canonical IMPI→SUPI derivation for
/// IMSI-based IMPIs is TS 23.003 §13.3 (the IMPI username part is the IMSI).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityContext {
    /// IMS Private User Identity, if known.
    pub impi: Option<Impi>,
    /// All IMS Public User Identities associated with the transaction.
    pub impu: Vec<Impu>,
    /// 5GC permanent identifier, if already de-concealed / derived.
    pub supi: Option<Supi>,
    /// 5GC concealed identifier, if the UE presented one.
    pub suci: Option<Suci>,
    /// Generic public identifier (MSISDN / external id), if known.
    pub gpsi: Option<Gpsi>,
}

impl IdentityContext {
    /// Derive a SUPI from an IMSI-based IMPI per TS 23.003 §13.3: for an IMPI
    /// of the form `<imsi>@ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org` the
    /// username part is the IMSI.
    ///
    /// Returns `None` when the IMPI username is not a plausible IMSI; callers
    /// must then resolve the SUPI via UDM instead of deriving it.
    pub fn derive_supi_from_impi(&self) -> Option<Supi> {
        let impi = self.impi.as_ref()?;
        let user = impi.as_str().split('@').next()?;
        Supi::new(format!("imsi-{user}")).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn impi_requires_nai_form() {
        assert!(Impi::new("001011234567890@ims.mnc001.mcc001.3gppnetwork.org").is_ok());
        assert!(Impi::new("no-realm").is_err());
        assert!(Impi::new("").is_err());
    }

    #[test]
    fn impu_requires_uri_scheme() {
        assert!(Impu::new("sip:alice@example.org").is_ok());
        assert!(Impu::new("tel:+14155550100").is_ok());
        assert!(Impu::new("alice@example.org").is_err());
    }

    #[test]
    fn supi_imsi_form_validated() {
        assert!(Supi::new("imsi-001011234567890").is_ok());
        assert!(Supi::new("imsi-12ab").is_err());
        assert!(Supi::new("imsi-1234").is_err()); // too short
        assert!(Supi::new("nai-user@realm").is_ok());
        assert!(Supi::new("gci-foo").is_err());
    }

    #[test]
    fn supi_derivation_from_imsi_impi() {
        let ctx = IdentityContext {
            impi: Some(
                Impi::new("001011234567890@ims.mnc001.mcc001.3gppnetwork.org")
                    .expect("test fixture IMPI is valid"),
            ),
            ..Default::default()
        };
        assert_eq!(
            ctx.derive_supi_from_impi()
                .expect("derivable from IMSI-based IMPI")
                .as_str(),
            "imsi-001011234567890"
        );
    }

    #[test]
    fn supi_derivation_rejects_non_imsi_user() {
        let ctx = IdentityContext {
            impi: Some(Impi::new("alice@example.org").expect("test fixture IMPI is valid")),
            ..Default::default()
        };
        assert!(ctx.derive_supi_from_impi().is_none());
    }

    #[test]
    fn gpsi_msisdn_form() {
        assert!(Gpsi::new("msisdn-14155550100").is_ok());
        assert!(Gpsi::new("msisdn-").is_err());
        assert!(Gpsi::new("extid-user@domain").is_ok());
    }
}
