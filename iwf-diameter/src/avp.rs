//! Zero-copy AVP codec (RFC 6733 §4).
//!
//! Decoding never copies payload octets: each [`Avp`] holds a
//! `bytes::Bytes` slice of the connection read buffer. Grouped AVPs are
//! decoded recursively with a hard depth bound. All length arithmetic is
//! checked; malformed input yields [`DiameterError`], never a panic.

use bytes::{BufMut, Bytes, BytesMut};

use crate::error::DiameterError;

/// Maximum grouped-AVP nesting accepted by the decoder. The deepest 3GPP
/// structure on Cx/Sh (`SIP-Auth-Data-Item` inside experimental groupings)
/// is 4 levels; 8 leaves headroom while bounding stack use.
pub const MAX_GROUP_DEPTH: usize = 8;

/// AVP flag octet (RFC 6733 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvpFlags(pub u8);

impl AvpFlags {
    /// Vendor-Specific bit.
    pub const VENDOR: u8 = 0x80;
    /// Mandatory bit.
    pub const MANDATORY: u8 = 0x40;
    /// Protected bit (end-to-end security; unused, must be preserved).
    pub const PROTECTED: u8 = 0x20;

    /// Whether the V bit is set.
    pub fn vendor(&self) -> bool {
        self.0 & Self::VENDOR != 0
    }

    /// Whether the M bit is set.
    pub fn mandatory(&self) -> bool {
        self.0 & Self::MANDATORY != 0
    }
}

/// One decoded AVP. Payload is a zero-copy slice of the source buffer.
#[derive(Debug, Clone)]
pub struct Avp {
    /// AVP Code.
    pub code: u32,
    /// Flag octet (V/M/P + reserved).
    pub flags: AvpFlags,
    /// Vendor-Id when the V bit is set.
    pub vendor_id: Option<u32>,
    /// Raw payload (excluding padding), sliced from the message buffer.
    pub data: Bytes,
}

impl Avp {
    /// Header size for this AVP's flag set: 8 octets, +4 with Vendor-Id.
    fn header_len(flags: u8) -> usize {
        if flags & AvpFlags::VENDOR != 0 {
            12
        } else {
            8
        }
    }

    /// Decode a single AVP starting at `offset` within `buf`.
    ///
    /// Returns the AVP and the offset of the next AVP (i.e. past padding).
    pub fn decode_at(buf: &Bytes, offset: usize) -> Result<(Avp, usize), DiameterError> {
        let remaining = buf.len() - offset;
        if remaining < 8 {
            return Err(DiameterError::TruncatedAvp {
                offset,
                reason: "fewer than 8 octets for AVP header",
            });
        }
        let code = u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        let flags = buf[offset + 4];
        let length =
            u32::from_be_bytes([0, buf[offset + 5], buf[offset + 6], buf[offset + 7]]) as usize;

        let hdr = Self::header_len(flags);
        if length < hdr {
            return Err(DiameterError::InvalidAvpLength { code, length });
        }
        if length > remaining {
            return Err(DiameterError::TruncatedAvp {
                offset,
                reason: "AVP length exceeds enclosing buffer",
            });
        }

        let vendor_id = if flags & AvpFlags::VENDOR != 0 {
            Some(u32::from_be_bytes([
                buf[offset + 8],
                buf[offset + 9],
                buf[offset + 10],
                buf[offset + 11],
            ]))
        } else {
            None
        };

        // Zero-copy: slice the payload out of the shared buffer.
        let data = buf.slice(offset + hdr..offset + length);

        // Padding to the next 32-bit boundary (RFC 6733 §4: pad octets are
        // not included in AVP Length but are part of the message).
        let padded = (length + 3) & !3;
        if padded > remaining {
            return Err(DiameterError::TruncatedAvp {
                offset,
                reason: "padding exceeds enclosing buffer",
            });
        }

        Ok((
            Avp {
                code,
                flags: AvpFlags(flags),
                vendor_id,
                data,
            },
            offset + padded,
        ))
    }

    /// Decode all AVPs in `buf` (a message body or grouped-AVP payload).
    pub fn decode_all(buf: &Bytes) -> Result<Vec<Avp>, DiameterError> {
        let mut avps = Vec::new();
        let mut offset = 0;
        while offset < buf.len() {
            let (avp, next) = Avp::decode_at(buf, offset)?;
            // decode_at always advances by at least one padded header.
            debug_assert!(next > offset);
            avps.push(avp);
            offset = next;
        }
        Ok(avps)
    }

    /// Encoded size on the wire, including padding.
    pub fn encoded_len(&self) -> usize {
        let len = Self::header_len(self.flags.0) + self.data.len();
        (len + 3) & !3
    }

    /// Append this AVP (with padding) to `out`.
    pub fn encode_into(&self, out: &mut BytesMut) {
        let hdr = Self::header_len(self.flags.0);
        let length = hdr + self.data.len();
        out.put_u32(self.code);
        out.put_u8(self.flags.0);
        // 24-bit length, big-endian.
        out.put_u8(((length >> 16) & 0xFF) as u8);
        out.put_u8(((length >> 8) & 0xFF) as u8);
        out.put_u8((length & 0xFF) as u8);
        if let Some(v) = self.vendor_id {
            out.put_u32(v);
        }
        out.put_slice(&self.data);
        let pad = ((length + 3) & !3) - length;
        out.put_bytes(0, pad);
    }

    // ---- typed accessors -------------------------------------------------

    /// Payload as UTF8String (RFC 6733 §4.3.1).
    pub fn as_utf8(&self) -> Result<&str, DiameterError> {
        std::str::from_utf8(&self.data).map_err(|_| DiameterError::WrongType {
            code: self.code,
            expected: "UTF8String",
        })
    }

    /// Payload as Unsigned32.
    pub fn as_u32(&self) -> Result<u32, DiameterError> {
        let arr: [u8; 4] = self
            .data
            .as_ref()
            .try_into()
            .map_err(|_| DiameterError::WrongType {
                code: self.code,
                expected: "Unsigned32",
            })?;
        Ok(u32::from_be_bytes(arr))
    }

    /// Payload as Unsigned64.
    pub fn as_u64(&self) -> Result<u64, DiameterError> {
        let arr: [u8; 8] = self
            .data
            .as_ref()
            .try_into()
            .map_err(|_| DiameterError::WrongType {
                code: self.code,
                expected: "Unsigned64",
            })?;
        Ok(u64::from_be_bytes(arr))
    }

    /// Payload as Enumerated (same wire form as Integer32).
    pub fn as_enum(&self) -> Result<i32, DiameterError> {
        let arr: [u8; 4] = self
            .data
            .as_ref()
            .try_into()
            .map_err(|_| DiameterError::WrongType {
                code: self.code,
                expected: "Enumerated",
            })?;
        Ok(i32::from_be_bytes(arr))
    }

    /// Payload as raw OctetString (zero-copy clone of the slice handle).
    pub fn as_octets(&self) -> Bytes {
        self.data.clone()
    }

    /// Decode the payload as a Grouped AVP (RFC 6733 §4.4) with the default
    /// depth budget.
    pub fn as_grouped(&self) -> Result<Vec<Avp>, DiameterError> {
        self.as_grouped_depth(MAX_GROUP_DEPTH)
    }

    /// Grouped decode with an explicit remaining-depth budget; called
    /// recursively by consumers walking nested groups.
    pub fn as_grouped_depth(&self, depth: usize) -> Result<Vec<Avp>, DiameterError> {
        if depth == 0 {
            return Err(DiameterError::NestingTooDeep(MAX_GROUP_DEPTH));
        }
        Avp::decode_all(&self.data)
    }
}

/// Typed constructors for outbound AVPs. Building copies the value once into
/// the message buffer at encode time; inbound parsing remains zero-copy.
#[derive(Debug, Clone)]
pub enum AvpValue {
    /// UTF8String / DiameterIdentity / DiameterURI.
    Utf8(String),
    /// Unsigned32 / Enumerated.
    U32(u32),
    /// Unsigned64.
    U64(u64),
    /// Enumerated (signed wire form).
    Enum(i32),
    /// OctetString.
    Octets(Bytes),
    /// Grouped.
    Grouped(Vec<Avp>),
}

impl AvpValue {
    /// Serialize to payload octets.
    pub fn into_bytes(self) -> Bytes {
        match self {
            AvpValue::Utf8(s) => Bytes::from(s.into_bytes()),
            AvpValue::U32(v) => Bytes::copy_from_slice(&v.to_be_bytes()),
            AvpValue::U64(v) => Bytes::copy_from_slice(&v.to_be_bytes()),
            AvpValue::Enum(v) => Bytes::copy_from_slice(&v.to_be_bytes()),
            AvpValue::Octets(b) => b,
            AvpValue::Grouped(avps) => {
                let len: usize = avps.iter().map(Avp::encoded_len).sum();
                let mut buf = BytesMut::with_capacity(len);
                for avp in &avps {
                    avp.encode_into(&mut buf);
                }
                buf.freeze()
            }
        }
    }
}

/// Build an AVP with the M bit set (the common case for 3GPP AVPs).
pub fn avp(code: u32, value: AvpValue) -> Avp {
    Avp {
        code,
        flags: AvpFlags(AvpFlags::MANDATORY),
        vendor_id: None,
        data: value.into_bytes(),
    }
}

/// Build a vendor-specific AVP for an arbitrary vendor with V+M bits.
pub fn avp_vendor(code: u32, vendor_id: u32, value: AvpValue) -> Avp {
    Avp {
        code,
        flags: AvpFlags(AvpFlags::VENDOR | AvpFlags::MANDATORY),
        vendor_id: Some(vendor_id),
        data: value.into_bytes(),
    }
}

/// Build a 3GPP vendor-specific AVP (Vendor-Id 10415) with V+M bits.
pub fn avp_3gpp(code: u32, value: AvpValue) -> Avp {
    Avp {
        code,
        flags: AvpFlags(AvpFlags::VENDOR | AvpFlags::MANDATORY),
        vendor_id: Some(crate::dictionary::VENDOR_3GPP),
        data: value.into_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_plain_avp() {
        let original = avp(264, AvpValue::Utf8("iwf.example.org".to_owned()));
        let mut buf = BytesMut::new();
        original.encode_into(&mut buf);
        assert_eq!(buf.len() % 4, 0, "padded to 32-bit boundary");
        let frozen = buf.freeze();
        let (decoded, next) = Avp::decode_at(&frozen, 0).expect("decode");
        assert_eq!(next, frozen.len());
        assert_eq!(decoded.code, 264);
        assert!(decoded.flags.mandatory());
        assert_eq!(decoded.vendor_id, None);
        assert_eq!(decoded.as_utf8().expect("utf8"), "iwf.example.org");
    }

    #[test]
    fn round_trip_vendor_avp() {
        let original = avp_3gpp(601, AvpValue::Utf8("sip:alice@example.org".to_owned()));
        let mut buf = BytesMut::new();
        original.encode_into(&mut buf);
        let frozen = buf.freeze();
        let (decoded, _) = Avp::decode_at(&frozen, 0).expect("decode");
        assert_eq!(decoded.vendor_id, Some(10415));
        assert!(decoded.flags.vendor());
    }

    #[test]
    fn grouped_avp_recursion() {
        let inner = avp(268, AvpValue::U32(2001));
        let group = avp(297, AvpValue::Grouped(vec![inner]));
        let mut buf = BytesMut::new();
        group.encode_into(&mut buf);
        let frozen = buf.freeze();
        let (decoded, _) = Avp::decode_at(&frozen, 0).expect("decode");
        let members = decoded.as_grouped().expect("grouped");
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].as_u32().expect("u32"), 2001);
    }

    #[test]
    fn rejects_undersized_declared_length() {
        // Header says length 4, below the 8-octet minimum.
        let raw = Bytes::from_static(&[0, 0, 1, 8, 0x40, 0, 0, 4, 0, 0, 0, 0]);
        assert!(matches!(
            Avp::decode_at(&raw, 0),
            Err(DiameterError::InvalidAvpLength { .. })
        ));
    }

    #[test]
    fn rejects_length_past_buffer() {
        // Declared length 64 but only 12 octets present.
        let raw = Bytes::from_static(&[0, 0, 1, 8, 0x40, 0, 0, 64, 0, 0, 0, 0]);
        assert!(matches!(
            Avp::decode_at(&raw, 0),
            Err(DiameterError::TruncatedAvp { .. })
        ));
    }

    #[test]
    fn rejects_vendor_flag_without_vendor_id_space() {
        // V bit set, declared length 8 (< 12-octet vendor header).
        let raw = Bytes::from_static(&[0, 0, 1, 8, 0x80, 0, 0, 8]);
        assert!(matches!(
            Avp::decode_at(&raw, 0),
            Err(DiameterError::InvalidAvpLength { .. })
        ));
    }

    #[test]
    fn zero_copy_payload_shares_buffer() {
        let original = avp(263, AvpValue::Utf8("session-id-0001".to_owned()));
        let mut buf = BytesMut::new();
        original.encode_into(&mut buf);
        let frozen = buf.freeze();
        let (decoded, _) = Avp::decode_at(&frozen, 0).expect("decode");
        // Bytes::slice keeps the same backing allocation: the payload pointer
        // must lie inside the frozen buffer.
        let base = frozen.as_ptr() as usize;
        let payload = decoded.data.as_ptr() as usize;
        assert!(payload >= base && payload < base + frozen.len());
    }
}
