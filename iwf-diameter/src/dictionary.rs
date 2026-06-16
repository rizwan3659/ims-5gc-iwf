//! Dictionary constants: application ids, command codes, AVP codes and
//! result codes for RFC 6733 base and the 3GPP applications the IWF speaks.
//!
//! Sources: RFC 6733 (base), TS 29.229 (Cx/Dx), TS 29.329 (Sh),
//! TS 29.273 (SWx), TS 29.109 (Zh), TS 29.230 (3GPP AVP/Experimental-Result
//! code registry).

/// 3GPP Vendor-Id (IANA enterprise number).
pub const VENDOR_3GPP: u32 = 10415;

// ---- Application ids ------------------------------------------------------

/// Diameter common messages (CER/DWR/DPR), RFC 6733.
pub const APP_BASE: u32 = 0;
/// Cx/Dx (TS 29.229 §6).
pub const APP_CX: u32 = 16_777_216;
/// Sh (TS 29.329 §6).
pub const APP_SH: u32 = 16_777_217;
/// Zh (TS 29.109).
pub const APP_ZH: u32 = 16_777_221;
/// SWx (TS 29.273 §8).
pub const APP_SWX: u32 = 16_777_265;
/// Relay application id (RFC 6733 §2.4).
pub const APP_RELAY: u32 = 0xFFFF_FFFF;

// ---- Base command codes (RFC 6733 §8.1) -----------------------------------

/// Capabilities-Exchange-Request/Answer.
pub const CMD_CER: u32 = 257;
/// Device-Watchdog-Request/Answer.
pub const CMD_DWR: u32 = 280;
/// Disconnect-Peer-Request/Answer.
pub const CMD_DPR: u32 = 282;

// ---- Cx command codes (TS 29.229 §6.1) --------------------------------------

/// User-Authorization-Request/Answer.
pub const CMD_UAR: u32 = 300;
/// Server-Assignment-Request/Answer.
pub const CMD_SAR: u32 = 301;
/// Location-Info-Request/Answer.
pub const CMD_LIR: u32 = 302;
/// Multimedia-Auth-Request/Answer.
pub const CMD_MAR: u32 = 303;
/// Registration-Termination-Request/Answer.
pub const CMD_RTR: u32 = 304;
/// Push-Profile-Request/Answer.
pub const CMD_PPR: u32 = 305;

// ---- Sh command codes (TS 29.329 §6.1) --------------------------------------

/// User-Data-Request/Answer.
pub const CMD_UDR: u32 = 306;
/// Profile-Update-Request/Answer.
pub const CMD_PUR: u32 = 307;
/// Subscribe-Notifications-Request/Answer.
pub const CMD_SNR: u32 = 308;
/// Push-Notification-Request/Answer.
pub const CMD_PNR: u32 = 309;

// ---- Base AVP codes (RFC 6733 §4.5) -----------------------------------------

/// User-Name (NAI / IMPI).
pub const AVP_USER_NAME: u32 = 1;
/// Host-IP-Address.
pub const AVP_HOST_IP_ADDRESS: u32 = 257;
/// Auth-Application-Id.
pub const AVP_AUTH_APPLICATION_ID: u32 = 258;
/// Vendor-Specific-Application-Id.
pub const AVP_VENDOR_SPECIFIC_APP_ID: u32 = 260;
/// Redirect-Host-Usage.
pub const AVP_SESSION_ID: u32 = 263;
/// Origin-Host.
pub const AVP_ORIGIN_HOST: u32 = 264;
/// Supported-Vendor-Id.
pub const AVP_SUPPORTED_VENDOR_ID: u32 = 265;
/// Vendor-Id.
pub const AVP_VENDOR_ID: u32 = 266;
/// Firmware-Revision.
pub const AVP_FIRMWARE_REVISION: u32 = 267;
/// Result-Code.
pub const AVP_RESULT_CODE: u32 = 268;
/// Product-Name.
pub const AVP_PRODUCT_NAME: u32 = 269;
/// Disconnect-Cause.
pub const AVP_DISCONNECT_CAUSE: u32 = 273;
/// Auth-Session-State.
pub const AVP_AUTH_SESSION_STATE: u32 = 277;
/// Origin-State-Id.
pub const AVP_ORIGIN_STATE_ID: u32 = 278;
/// Failed-AVP.
pub const AVP_FAILED_AVP: u32 = 279;
/// Destination-Realm.
pub const AVP_DESTINATION_REALM: u32 = 283;
/// Destination-Host.
pub const AVP_DESTINATION_HOST: u32 = 293;
/// Origin-Realm.
pub const AVP_ORIGIN_REALM: u32 = 296;
/// Experimental-Result (grouped).
pub const AVP_EXPERIMENTAL_RESULT: u32 = 297;
/// Experimental-Result-Code.
pub const AVP_EXPERIMENTAL_RESULT_CODE: u32 = 298;
/// Error-Message.
pub const AVP_ERROR_MESSAGE: u32 = 281;

// ---- 3GPP AVP codes (TS 29.229 §6.3, TS 29.329 §6.3; Vendor-Id 10415) -------

/// Public-Identity (TS 29.229 §6.3.2).
pub const AVP_PUBLIC_IDENTITY: u32 = 601;
/// Server-Name (TS 29.229 §6.3.3).
pub const AVP_SERVER_NAME: u32 = 602;
/// Server-Capabilities (TS 29.229 §6.3.4).
pub const AVP_SERVER_CAPABILITIES: u32 = 603;
/// User-Data (Sh, TS 29.329 §6.3.1; Cx TS 29.229 §6.3.6).
pub const AVP_USER_DATA: u32 = 606;
/// SIP-Number-Auth-Items (TS 29.229 §6.3.8).
pub const AVP_SIP_NUMBER_AUTH_ITEMS: u32 = 607;
/// SIP-Authentication-Scheme (TS 29.229 §6.3.9).
pub const AVP_SIP_AUTH_SCHEME: u32 = 608;
/// SIP-Authenticate (TS 29.229 §6.3.10).
pub const AVP_SIP_AUTHENTICATE: u32 = 609;
/// SIP-Authorization (TS 29.229 §6.3.11).
pub const AVP_SIP_AUTHORIZATION: u32 = 610;
/// SIP-Auth-Data-Item (grouped, TS 29.229 §6.3.13).
pub const AVP_SIP_AUTH_DATA_ITEM: u32 = 612;
/// Server-Assignment-Type (TS 29.229 §6.3.15).
pub const AVP_SERVER_ASSIGNMENT_TYPE: u32 = 614;
/// Deregistration-Reason (grouped, TS 29.229 §6.3.16).
pub const AVP_DEREGISTRATION_REASON: u32 = 615;
/// Reason-Code (TS 29.229 §6.3.17).
pub const AVP_REASON_CODE: u32 = 616;
/// Reason-Info (TS 29.229 §6.3.18).
pub const AVP_REASON_INFO: u32 = 617;
/// Confidentiality-Key (TS 29.229 §6.3.27).
pub const AVP_CONFIDENTIALITY_KEY: u32 = 625;
/// Integrity-Key (TS 29.229 §6.3.28).
pub const AVP_INTEGRITY_KEY: u32 = 626;
/// User-Authorization-Type (TS 29.229 §6.3.24).
pub const AVP_USER_AUTHORIZATION_TYPE: u32 = 623;
/// Data-Reference (Sh, TS 29.329 §6.3.4).
pub const AVP_DATA_REFERENCE: u32 = 703;
/// User-Identity (grouped, Sh, TS 29.329 §6.3.2).
pub const AVP_USER_IDENTITY: u32 = 700;
/// MSISDN (Sh, TS 29.329 §6.3.2A).
pub const AVP_MSISDN: u32 = 701;
/// Subs-Req-Type (Sh, TS 29.329 §6.3.6).
pub const AVP_SUBS_REQ_TYPE: u32 = 705;

// ---- Result codes -----------------------------------------------------------

/// DIAMETER_SUCCESS (RFC 6733 §7.1.2).
pub const RC_SUCCESS: u32 = 2001;
/// DIAMETER_COMMAND_UNSUPPORTED (RFC 6733 §7.1.3).
pub const RC_COMMAND_UNSUPPORTED: u32 = 3001;
/// DIAMETER_UNABLE_TO_DELIVER.
pub const RC_UNABLE_TO_DELIVER: u32 = 3002;
/// DIAMETER_TOO_BUSY.
pub const RC_TOO_BUSY: u32 = 3004;
/// DIAMETER_APPLICATION_UNSUPPORTED.
pub const RC_APPLICATION_UNSUPPORTED: u32 = 3007;
/// DIAMETER_INVALID_AVP_VALUE (RFC 6733 §7.1.5).
pub const RC_INVALID_AVP_VALUE: u32 = 5004;
/// DIAMETER_MISSING_AVP.
pub const RC_MISSING_AVP: u32 = 5005;
/// DIAMETER_UNABLE_TO_COMPLY.
pub const RC_UNABLE_TO_COMPLY: u32 = 5012;
/// DIAMETER_ERROR_USER_UNKNOWN (Experimental, TS 29.229 §6.2.2.1).
pub const ERC_USER_UNKNOWN: u32 = 5001;
/// DIAMETER_ERROR_IDENTITIES_DONT_MATCH (TS 29.229 §6.2.2.2).
pub const ERC_IDENTITIES_DONT_MATCH: u32 = 5002;
/// DIAMETER_FIRST_REGISTRATION (Experimental success, TS 29.229 §6.2.1.1).
pub const ERC_FIRST_REGISTRATION: u32 = 2001;
/// DIAMETER_SUBSEQUENT_REGISTRATION (TS 29.229 §6.2.1.2).
pub const ERC_SUBSEQUENT_REGISTRATION: u32 = 2002;

/// Disconnect-Cause values (RFC 6733 §5.4.3).
pub mod disconnect_cause {
    /// REBOOTING — planned restart; peer should reconnect promptly.
    pub const REBOOTING: u32 = 0;
    /// BUSY — peer overloaded.
    pub const BUSY: u32 = 1;
    /// DO_NOT_WANT_TO_TALK_TO_YOU — administrative removal.
    pub const DO_NOT_WANT_TO_TALK_TO_YOU: u32 = 2;
}

/// Server-Assignment-Type values (TS 29.229 §6.3.15). The IWF maps these onto
/// the Nhss_imsUECM operation for an SAR (TS 29.562 §6): REGISTRATION /
/// RE_REGISTRATION → UECM Registration; the deregistration family → UECM
/// Deregistration; the rest → UECM Update. (Used by the `set_var` rule action.)
pub mod server_assignment_type {
    /// NO_ASSIGNMENT.
    pub const NO_ASSIGNMENT: i32 = 0;
    /// REGISTRATION.
    pub const REGISTRATION: i32 = 1;
    /// RE_REGISTRATION.
    pub const RE_REGISTRATION: i32 = 2;
    /// UNREGISTERED_USER.
    pub const UNREGISTERED_USER: i32 = 3;
    /// TIMEOUT_DEREGISTRATION.
    pub const TIMEOUT_DEREGISTRATION: i32 = 4;
    /// USER_DEREGISTRATION.
    pub const USER_DEREGISTRATION: i32 = 5;
    /// TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME.
    pub const TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME: i32 = 6;
    /// USER_DEREGISTRATION_STORE_SERVER_NAME.
    pub const USER_DEREGISTRATION_STORE_SERVER_NAME: i32 = 7;
    /// ADMINISTRATIVE_DEREGISTRATION.
    pub const ADMINISTRATIVE_DEREGISTRATION: i32 = 8;
    /// AUTHENTICATION_FAILURE.
    pub const AUTHENTICATION_FAILURE: i32 = 9;
    /// AUTHENTICATION_TIMEOUT.
    pub const AUTHENTICATION_TIMEOUT: i32 = 10;
    /// DEREGISTRATION_TOO_MUCH_DATA.
    pub const DEREGISTRATION_TOO_MUCH_DATA: i32 = 11;
}

/// Data-Reference values (TS 29.329 §6.3.4) — select the Sh data item and,
/// per TS 29.562 §6, the Nhss_imsSDM Get resource (the value → resource
/// mapping ships as a `set_var` table in `config/rules-nhss.yaml`).
pub mod data_reference {
    /// RepositoryData.
    pub const REPOSITORY_DATA: i32 = 0;
    /// IMSPublicIdentity.
    pub const IMS_PUBLIC_IDENTITY: i32 = 10;
    /// IMSUserState.
    pub const IMS_USER_STATE: i32 = 11;
    /// S-CSCFName.
    pub const SCSCF_NAME: i32 = 12;
    /// InitialFilterCriteria.
    pub const INITIAL_FILTER_CRITERIA: i32 = 13;
    /// LocationInformation.
    pub const LOCATION_INFORMATION: i32 = 14;
    /// UserState.
    pub const USER_STATE: i32 = 15;
    /// ChargingInformation.
    pub const CHARGING_INFORMATION: i32 = 16;
    /// MSISDN.
    pub const MSISDN: i32 = 17;
    /// PSIActivation.
    pub const PSI_ACTIVATION: i32 = 18;
    /// DSAI.
    pub const DSAI: i32 = 19;
    /// ServiceLevelTraceInfo.
    pub const SERVICE_LEVEL_TRACE_INFO: i32 = 21;
    /// IPAddressSecureBindingInformation.
    pub const IP_ADDRESS_SECURE_BINDING_INFORMATION: i32 = 22;
    /// TADSInformation.
    pub const TADS_INFORMATION: i32 = 23;
    /// STN-SR.
    pub const STN_SR: i32 = 24;
    /// UE-SRVCC-Capability.
    pub const UE_SRVCC_CAPABILITY: i32 = 25;
    /// CSRN.
    pub const CSRN: i32 = 26;
    /// ReferenceLocationInformation.
    pub const REFERENCE_LOCATION_INFORMATION: i32 = 27;
}
