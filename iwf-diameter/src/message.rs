//! Diameter message codec: 20-octet header (RFC 6733 §3) plus AVP body.

use bytes::{BufMut, Bytes, BytesMut};

use crate::avp::{Avp, AvpValue};
use crate::dictionary as dict;
use crate::error::DiameterError;

/// Command flag octet (RFC 6733 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommandFlags(pub u8);

impl CommandFlags {
    /// Request bit.
    pub const REQUEST: u8 = 0x80;
    /// Proxiable bit.
    pub const PROXIABLE: u8 = 0x40;
    /// Error bit.
    pub const ERROR: u8 = 0x20;
    /// Potentially re-transmitted bit.
    pub const RETRANSMITTED: u8 = 0x10;

    /// Whether this message is a request.
    pub fn request(&self) -> bool {
        self.0 & Self::REQUEST != 0
    }

    /// Whether the error bit is set.
    pub fn error(&self) -> bool {
        self.0 & Self::ERROR != 0
    }
}

/// Decoded Diameter header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Command flags (R/P/E/T).
    pub flags: CommandFlags,
    /// 24-bit Command-Code.
    pub command: u32,
    /// Application-Id.
    pub application: u32,
    /// Hop-by-Hop identifier — correlation key for pending transactions.
    pub hop_by_hop: u32,
    /// End-to-End identifier.
    pub end_to_end: u32,
}

/// Size of the fixed Diameter header in octets.
pub const HEADER_LEN: usize = 20;

/// A fully decoded message. AVP payloads alias the original frame buffer.
#[derive(Debug, Clone)]
pub struct Message {
    /// Fixed header.
    pub header: Header,
    /// Top-level AVPs in wire order.
    pub avps: Vec<Avp>,
}

impl Message {
    /// Decode one complete frame. `frame` must contain exactly one message
    /// (the transport layer guarantees this by reading Message-Length).
    pub fn decode(frame: Bytes) -> Result<Message, DiameterError> {
        if frame.len() < HEADER_LEN {
            return Err(DiameterError::TruncatedHeader(frame.len()));
        }
        if frame[0] != 1 {
            return Err(DiameterError::BadVersion(frame[0]));
        }
        let declared = u32::from_be_bytes([0, frame[1], frame[2], frame[3]]) as usize;
        if declared != frame.len() {
            return Err(DiameterError::BadMessageLength {
                declared,
                actual: frame.len(),
            });
        }
        if declared % 4 != 0 {
            return Err(DiameterError::UnalignedLength(declared));
        }
        let header = Header {
            flags: CommandFlags(frame[4]),
            command: u32::from_be_bytes([0, frame[5], frame[6], frame[7]]),
            application: u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]),
            hop_by_hop: u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]),
            end_to_end: u32::from_be_bytes([frame[16], frame[17], frame[18], frame[19]]),
        };
        let body = frame.slice(HEADER_LEN..);
        let avps = Avp::decode_all(&body)?;
        Ok(Message { header, avps })
    }

    /// Encode to a single contiguous frame.
    pub fn encode(&self) -> Bytes {
        let body_len: usize = self.avps.iter().map(Avp::encoded_len).sum();
        let total = HEADER_LEN + body_len;
        let mut buf = BytesMut::with_capacity(total);
        buf.put_u8(1);
        buf.put_u8(((total >> 16) & 0xFF) as u8);
        buf.put_u8(((total >> 8) & 0xFF) as u8);
        buf.put_u8((total & 0xFF) as u8);
        buf.put_u8(self.header.flags.0);
        buf.put_u8(((self.header.command >> 16) & 0xFF) as u8);
        buf.put_u8(((self.header.command >> 8) & 0xFF) as u8);
        buf.put_u8((self.header.command & 0xFF) as u8);
        buf.put_u32(self.header.application);
        buf.put_u32(self.header.hop_by_hop);
        buf.put_u32(self.header.end_to_end);
        for avp in &self.avps {
            avp.encode_into(&mut buf);
        }
        buf.freeze()
    }

    /// First top-level AVP with `code` (and matching vendor when given).
    pub fn find(&self, code: u32, vendor: Option<u32>) -> Option<&Avp> {
        self.avps
            .iter()
            .find(|a| a.code == code && a.vendor_id == vendor)
    }

    /// All top-level AVPs with `code`/`vendor` (e.g. repeated
    /// `Public-Identity`).
    pub fn find_all(&self, code: u32, vendor: Option<u32>) -> Vec<&Avp> {
        self.avps
            .iter()
            .filter(|a| a.code == code && a.vendor_id == vendor)
            .collect()
    }

    /// `Session-Id` AVP value, when present (RFC 6733 §8.8).
    pub fn session_id(&self) -> Option<&str> {
        self.find(dict::AVP_SESSION_ID, None)
            .and_then(|a| a.as_utf8().ok())
    }

    /// `Result-Code` AVP value, when present (RFC 6733 §7.1).
    pub fn result_code(&self) -> Option<u32> {
        self.find(dict::AVP_RESULT_CODE, None)
            .and_then(|a| a.as_u32().ok())
    }
}

/// Fluent builder for outbound messages.
#[derive(Debug)]
pub struct MessageBuilder {
    header: Header,
    avps: Vec<Avp>,
}

impl MessageBuilder {
    /// Start a request for `command` within `application`.
    pub fn request(command: u32, application: u32) -> Self {
        MessageBuilder {
            header: Header {
                flags: CommandFlags(CommandFlags::REQUEST | CommandFlags::PROXIABLE),
                command,
                application,
                hop_by_hop: 0,
                end_to_end: 0,
            },
            avps: Vec::new(),
        }
    }

    /// Start the answer to `request`, copying command, application and both
    /// correlation identifiers per RFC 6733 §6.2.
    pub fn answer_to(request: &Header) -> Self {
        MessageBuilder {
            header: Header {
                flags: CommandFlags(request.flags.0 & CommandFlags::PROXIABLE),
                command: request.command,
                application: request.application,
                hop_by_hop: request.hop_by_hop,
                end_to_end: request.end_to_end,
            },
            avps: Vec::new(),
        }
    }

    /// Set hop-by-hop / end-to-end identifiers (requests only; answers copy
    /// them from the request).
    pub fn ids(mut self, hop_by_hop: u32, end_to_end: u32) -> Self {
        self.header.hop_by_hop = hop_by_hop;
        self.header.end_to_end = end_to_end;
        self
    }

    /// Set the error bit (protocol-error answers, RFC 6733 §7.2).
    pub fn error_bit(mut self) -> Self {
        self.header.flags.0 |= CommandFlags::ERROR;
        self
    }

    /// Append a pre-built AVP.
    pub fn avp(mut self, avp: Avp) -> Self {
        self.avps.push(avp);
        self
    }

    /// Append a standard (non-vendor) AVP with the M bit.
    pub fn std(self, code: u32, value: AvpValue) -> Self {
        self.avp(crate::avp::avp(code, value))
    }

    /// Append a 3GPP vendor AVP with V+M bits.
    pub fn tgpp(self, code: u32, value: AvpValue) -> Self {
        self.avp(crate::avp::avp_3gpp(code, value))
    }

    /// Finalize.
    pub fn build(self) -> Message {
        Message {
            header: self.header,
            avps: self.avps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> Message {
        MessageBuilder::request(dict::CMD_UAR, dict::APP_CX)
            .ids(0x1111_2222, 0x3333_4444)
            .std(
                dict::AVP_SESSION_ID,
                AvpValue::Utf8("iwf.example.org;1;1".to_owned()),
            )
            .std(
                dict::AVP_ORIGIN_HOST,
                AvpValue::Utf8("iwf.example.org".to_owned()),
            )
            .std(
                dict::AVP_ORIGIN_REALM,
                AvpValue::Utf8("example.org".to_owned()),
            )
            .std(
                dict::AVP_DESTINATION_REALM,
                AvpValue::Utf8("ims.example.org".to_owned()),
            )
            .std(
                dict::AVP_USER_NAME,
                AvpValue::Utf8("alice@example.org".to_owned()),
            )
            .tgpp(
                dict::AVP_PUBLIC_IDENTITY,
                AvpValue::Utf8("sip:alice@example.org".to_owned()),
            )
            .build()
    }

    #[test]
    fn message_round_trip() {
        let msg = sample_request();
        let wire = msg.encode();
        assert_eq!(wire.len() % 4, 0);
        let decoded = Message::decode(wire).expect("decode");
        assert_eq!(decoded.header, msg.header);
        assert_eq!(decoded.avps.len(), msg.avps.len());
        assert_eq!(decoded.session_id(), Some("iwf.example.org;1;1"));
        assert_eq!(
            decoded
                .find(dict::AVP_PUBLIC_IDENTITY, Some(dict::VENDOR_3GPP))
                .and_then(|a| a.as_utf8().ok()),
            Some("sip:alice@example.org")
        );
    }

    #[test]
    fn answer_copies_correlation_ids() {
        let req = sample_request();
        let ans = MessageBuilder::answer_to(&req.header)
            .std(dict::AVP_RESULT_CODE, AvpValue::U32(dict::RC_SUCCESS))
            .build();
        assert!(!ans.header.flags.request());
        assert_eq!(ans.header.hop_by_hop, req.header.hop_by_hop);
        assert_eq!(ans.header.end_to_end, req.header.end_to_end);
        assert_eq!(ans.result_code(), Some(2001));
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        let msg = sample_request();
        let wire = msg.encode();
        let truncated = wire.slice(..wire.len() - 4);
        assert!(matches!(
            Message::decode(truncated),
            Err(DiameterError::BadMessageLength { .. })
        ));
    }

    #[test]
    fn decode_rejects_bad_version() {
        let msg = sample_request();
        let mut wire = BytesMut::from(&msg.encode()[..]);
        wire[0] = 2;
        assert!(matches!(
            Message::decode(wire.freeze()),
            Err(DiameterError::BadVersion(2))
        ));
    }
}
