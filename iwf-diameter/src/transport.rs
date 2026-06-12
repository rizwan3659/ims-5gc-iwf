//! Frame-level transport: length-delimited Diameter framing over any
//! `AsyncRead`/`AsyncWrite` (plain TCP or TLS — the stream is generic, so
//! `tokio_rustls::TlsStream<TcpStream>` plugs in unchanged).
//!
//! The read path allocates exactly one `BytesMut` per frame; the codec then
//! slices AVPs out of it zero-copy. Frames above `max_frame` are rejected
//! before allocation (DoS guard).

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::DiameterError;
use crate::message::{Message, HEADER_LEN};

/// Default upper bound for one Diameter message. TS 29.229 user data can be
/// tens of kilobytes; 1 MiB leaves ample headroom while bounding memory.
pub const DEFAULT_MAX_FRAME: usize = 1024 * 1024;

/// Read exactly one Diameter frame from `stream`.
///
/// Returns `Ok(None)` on clean EOF at a frame boundary (peer closed), the
/// decoded frame bytes otherwise. The returned buffer is the *only*
/// allocation for the message; `Message::decode` slices it zero-copy.
pub async fn read_frame<S>(stream: &mut S, max_frame: usize) -> Result<Option<Bytes>, DiameterError>
where
    S: AsyncRead + Unpin,
{
    let mut head = [0u8; 4];
    // First octet: detect clean EOF before a frame starts.
    if stream.read(&mut head[..1]).await? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut head[1..]).await?;

    if head[0] != 1 {
        return Err(DiameterError::BadVersion(head[0]));
    }
    let declared = u32::from_be_bytes([0, head[1], head[2], head[3]]) as usize;
    if declared < HEADER_LEN {
        return Err(DiameterError::BadMessageLength {
            declared,
            actual: HEADER_LEN,
        });
    }
    if declared % 4 != 0 {
        return Err(DiameterError::UnalignedLength(declared));
    }
    if declared > max_frame {
        return Err(DiameterError::FrameTooLarge {
            got: declared,
            max: max_frame,
        });
    }

    let mut buf = BytesMut::with_capacity(declared);
    buf.extend_from_slice(&head);
    buf.resize(declared, 0);
    stream.read_exact(&mut buf[4..]).await?;
    Ok(Some(buf.freeze()))
}

/// Write one already-encoded message to `stream`.
pub async fn write_frame<S>(stream: &mut S, msg: &Message) -> Result<(), DiameterError>
where
    S: AsyncWrite + Unpin,
{
    let wire = msg.encode();
    stream.write_all(&wire).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::avp::AvpValue;
    use crate::dictionary as dict;
    use crate::message::MessageBuilder;

    fn sample() -> Message {
        MessageBuilder::request(dict::CMD_UAR, dict::APP_CX)
            .ids(42, 43)
            .std(
                dict::AVP_ORIGIN_HOST,
                AvpValue::Utf8("iwf.example.org".to_owned()),
            )
            .build()
    }

    #[tokio::test]
    async fn frame_round_trip_over_duplex() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let msg = sample();
        write_frame(&mut client, &msg).await.expect("write");
        let frame = read_frame(&mut server, DEFAULT_MAX_FRAME)
            .await
            .expect("read")
            .expect("not EOF");
        let decoded = Message::decode(frame).expect("decode");
        assert_eq!(decoded.header, msg.header);
    }

    #[tokio::test]
    async fn clean_eof_yields_none() {
        let (client, mut server) = tokio::io::duplex(64);
        drop(client);
        assert!(read_frame(&mut server, DEFAULT_MAX_FRAME)
            .await
            .expect("eof is not an error")
            .is_none());
    }

    #[tokio::test]
    async fn oversized_frame_rejected_before_allocation() {
        let (mut client, mut server) = tokio::io::duplex(64);
        // Header declaring a 16 MiB message.
        client
            .write_all(&[1, 0xFF, 0xFF, 0xFC])
            .await
            .expect("write");
        let err = read_frame(&mut server, DEFAULT_MAX_FRAME).await;
        assert!(matches!(err, Err(DiameterError::FrameTooLarge { .. })));
    }

    #[tokio::test]
    async fn bad_version_rejected() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&[9, 0, 0, 20]).await.expect("write");
        assert!(matches!(
            read_frame(&mut server, DEFAULT_MAX_FRAME).await,
            Err(DiameterError::BadVersion(9))
        ));
    }
}
