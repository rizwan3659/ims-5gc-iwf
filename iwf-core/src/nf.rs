//! 5GC network-function taxonomy used by routing, discovery, and rules.

use serde::{Deserialize, Serialize};

/// Network function types the IWF interacts with (TS 29.510 §6.1.6.3.3
/// `NFType` enumeration, subset relevant to IMS interworking).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NfType {
    /// Unified Data Management (Nudm, TS 29.503).
    Udm,
    /// Unified Data Repository (Nudr, TS 29.504/29.519).
    Udr,
    /// Authentication Server Function (Nausf, TS 29.509).
    Ausf,
    /// Access and Mobility Management Function (Namf, TS 29.518).
    Amf,
    /// Policy Control Function (Npcf, TS 29.507/29.512).
    Pcf,
    /// NF Repository Function (Nnrf, TS 29.510).
    Nrf,
    /// Home Subscriber Server exposing the Nhss IMS services
    /// (TS 29.562: Nhss_imsUECM / Nhss_imsSDM / Nhss_imsUEAU). This is the
    /// canonical producer for IMS interworking (Cx/Sh → Nhss).
    Hss,
}

impl NfType {
    /// Wire form used in NRF discovery queries (`target-nf-type`).
    pub fn as_str(&self) -> &'static str {
        match self {
            NfType::Udm => "UDM",
            NfType::Udr => "UDR",
            NfType::Ausf => "AUSF",
            NfType::Amf => "AMF",
            NfType::Pcf => "PCF",
            NfType::Nrf => "NRF",
            NfType::Hss => "HSS",
        }
    }
}

impl std::fmt::Display for NfType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for NfType {
    type Err = crate::error::CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "UDM" => Ok(NfType::Udm),
            "UDR" => Ok(NfType::Udr),
            "AUSF" => Ok(NfType::Ausf),
            "AMF" => Ok(NfType::Amf),
            "PCF" => Ok(NfType::Pcf),
            "NRF" => Ok(NfType::Nrf),
            "HSS" => Ok(NfType::Hss),
            _ => Err(crate::error::CoreError::MissingElement("known NF type")),
        }
    }
}
