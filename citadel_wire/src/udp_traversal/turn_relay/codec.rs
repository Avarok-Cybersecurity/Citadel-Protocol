//! STUN (RFC 8489) message construction/parsing for TURN (RFC 8656), plus ChannelData framing.
//!
//! The STUN message codec, MESSAGE-INTEGRITY (HMAC-SHA1 with the RFC 8489 §9.2.2 long-term key
//! MD5(username:realm:password)) and FINGERPRINT come from the `stun` crate already in the tree;
//! this module only adds the TURN attributes it lacks a typed setter for and the ChannelData
//! framing. Known-answer tests against RFC 5769 pin both directions.

use std::net::SocketAddr;
use std::time::Duration;

pub(crate) use stun::agent::TransactionId;
use stun::attributes::*;
use stun::error_code::ErrorCodeAttribute;
use stun::fingerprint::FINGERPRINT;
use stun::integrity::MessageIntegrity;
pub(crate) use stun::message::Method;
use stun::message::{Getter, Message, MessageClass, MessageType, Setter};
use stun::textattrs::TextAttribute;
use stun::xoraddr::XorMappedAddress;

pub(crate) use stun::message::{
    CLASS_ERROR_RESPONSE, CLASS_INDICATION, CLASS_REQUEST, CLASS_SUCCESS_RESPONSE, METHOD_ALLOCATE,
    METHOD_BINDING, METHOD_CHANNEL_BIND, METHOD_CREATE_PERMISSION, METHOD_DATA, METHOD_REFRESH,
    METHOD_SEND,
};

/// RFC 8656 §12: ChannelData header (channel number + length).
pub const CHANNEL_DATA_HEADER_LEN: usize = 4;
/// RFC 8656 §12: the channel-number range a client may bind.
pub(crate) const CHANNEL_MIN: u16 = 0x4000;
pub(crate) const CHANNEL_MAX: u16 = 0x4FFF;
/// RFC 8656 §14.7: REQUESTED-TRANSPORT protocol number for UDP.
const PROTO_UDP: u8 = 17;
const STUN_HEADER_LEN: usize = 20;

pub(crate) type CodecResult<T> = Result<T, std::io::Error>;

fn io_err(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

/// Long-term credential state learned from the server's 401 (REALM + NONCE).
#[derive(Clone)]
pub(crate) struct LongTermAuth {
    pub username: String,
    pub realm: String,
    pub nonce: String,
    key: MessageIntegrity,
}

impl LongTermAuth {
    pub fn new(username: &str, password: &str, realm: String, nonce: String) -> Self {
        let key = MessageIntegrity::new_long_term_integrity(
            username.to_string(),
            realm.clone(),
            password.to_string(),
        );
        Self {
            username: username.to_string(),
            realm,
            nonce,
            key,
        }
    }

    /// Verifies MESSAGE-INTEGRITY of a message received from the server.
    pub fn verify(&self, m: &mut Message) -> CodecResult<()> {
        self.key.check(m).map_err(io_err)
    }
}

/// A TURN attribute the `stun` crate has no typed setter for.
pub(crate) enum Attr {
    RequestedTransportUdp,
    Lifetime(Duration),
    ChannelNumber(u16),
    XorPeerAddress(SocketAddr),
    Data(Vec<u8>),
}

impl Attr {
    fn add_to(&self, m: &mut Message) -> CodecResult<()> {
        match self {
            Attr::RequestedTransportUdp => m.add(ATTR_REQUESTED_TRANSPORT, &[PROTO_UDP, 0, 0, 0]),
            Attr::Lifetime(d) => {
                let secs = u32::try_from(d.as_secs()).unwrap_or(u32::MAX);
                m.add(ATTR_LIFETIME, &secs.to_be_bytes())
            }
            Attr::ChannelNumber(n) => {
                let b = n.to_be_bytes();
                m.add(ATTR_CHANNEL_NUMBER, &[b[0], b[1], 0, 0])
            }
            Attr::XorPeerAddress(addr) => XorMappedAddress {
                ip: addr.ip(),
                port: addr.port(),
            }
            .add_to_as(m, ATTR_XOR_PEER_ADDRESS)
            .map_err(io_err)?,
            Attr::Data(d) => m.add(ATTR_DATA, d),
        }
        Ok(())
    }
}

/// Builds a STUN message. Requests carrying `auth` get USERNAME, NONCE, REALM and
/// MESSAGE-INTEGRITY (in that order, as in RFC 5769 §2.4); `fingerprint` appends FINGERPRINT last.
pub(crate) fn build(
    method: Method,
    class: MessageClass,
    transaction_id: TransactionId,
    attrs: &[Attr],
    auth: Option<&LongTermAuth>,
    fingerprint: bool,
) -> CodecResult<Message> {
    let mut m = Message::new();
    m.typ = MessageType::new(method, class);
    m.transaction_id = transaction_id;
    m.write_header();
    for attr in attrs {
        attr.add_to(&mut m)?;
    }
    if let Some(auth) = auth {
        TextAttribute::new(ATTR_USERNAME, auth.username.clone())
            .add_to(&mut m)
            .map_err(io_err)?;
        TextAttribute::new(ATTR_NONCE, auth.nonce.clone())
            .add_to(&mut m)
            .map_err(io_err)?;
        TextAttribute::new(ATTR_REALM, auth.realm.clone())
            .add_to(&mut m)
            .map_err(io_err)?;
        auth.key.add_to(&mut m).map_err(io_err)?;
    }
    if fingerprint {
        FINGERPRINT.add_to(&mut m).map_err(io_err)?;
    }
    Ok(m)
}

pub(crate) fn parse(bytes: &[u8]) -> CodecResult<Message> {
    let mut m = Message::new();
    m.unmarshal_binary(bytes).map_err(io_err)?;
    Ok(m)
}

/// Verifies FINGERPRINT when present (RFC 8489 §14.7 makes it optional for TURN).
pub(crate) fn check_fingerprint_if_present(m: &Message) -> CodecResult<()> {
    if m.contains(ATTR_FINGERPRINT) {
        FINGERPRINT.check(m).map_err(io_err)?;
    }
    Ok(())
}

pub(crate) fn error_code(m: &Message) -> Option<(u16, String)> {
    let mut e = ErrorCodeAttribute::default();
    e.get_from(m).ok()?;
    Some((e.code.0, String::from_utf8_lossy(&e.reason).into_owned()))
}

pub(crate) fn text(m: &Message, attr: AttrType) -> Option<String> {
    TextAttribute::get_from_as(m, attr).ok().map(|t| t.text)
}

pub(crate) fn xor_address(m: &Message, attr: AttrType) -> Option<SocketAddr> {
    let mut a = XorMappedAddress::default();
    a.get_from_as(m, attr).ok()?;
    Some(SocketAddr::new(a.ip, a.port))
}

pub(crate) fn lifetime(m: &Message) -> Option<Duration> {
    let v = m.get(ATTR_LIFETIME).ok()?;
    let secs = u32::from_be_bytes(v.get(..4)?.try_into().ok()?);
    Some(Duration::from_secs(secs as u64))
}

pub(crate) fn data(m: &Message) -> Option<Vec<u8>> {
    m.get(ATTR_DATA).ok()
}

/// ChannelData message (RFC 8656 §12.4). Over TCP/TLS the frame is padded to a multiple of 4
/// (§12.5); over UDP it is not.
pub(crate) fn encode_channel_data(channel: u16, payload: &[u8], pad: bool) -> CodecResult<Vec<u8>> {
    let len = u16::try_from(payload.len()).map_err(io_err)?;
    let padded = if pad {
        payload.len().div_ceil(4) * 4
    } else {
        payload.len()
    };
    let mut out = Vec::with_capacity(CHANNEL_DATA_HEADER_LEN + padded);
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out.resize(CHANNEL_DATA_HEADER_LEN + padded, 0);
    Ok(out)
}

/// What a datagram (or stream frame) from the server holds.
pub(crate) enum Inbound<'a> {
    Stun,
    ChannelData { channel: u16, payload: &'a [u8] },
}

pub(crate) fn classify(buf: &[u8]) -> CodecResult<Inbound<'_>> {
    let first = *buf.first().ok_or_else(|| io_err("empty frame"))?;
    match first >> 6 {
        0b00 => Ok(Inbound::Stun),
        0b01 => {
            if buf.len() < CHANNEL_DATA_HEADER_LEN {
                return Err(io_err("short ChannelData"));
            }
            let channel = u16::from_be_bytes([buf[0], buf[1]]);
            let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            let payload = buf
                .get(CHANNEL_DATA_HEADER_LEN..CHANNEL_DATA_HEADER_LEN + len)
                .ok_or_else(|| io_err("truncated ChannelData"))?;
            Ok(Inbound::ChannelData { channel, payload })
        }
        _ => Err(io_err("frame is neither STUN nor ChannelData")),
    }
}

/// On a stream transport, the full length of the frame starting with these 4 bytes.
pub(crate) fn stream_frame_len(header: [u8; 4]) -> CodecResult<usize> {
    let len = u16::from_be_bytes([header[2], header[3]]) as usize;
    match header[0] >> 6 {
        0b00 => Ok(STUN_HEADER_LEN + len),
        0b01 => Ok(CHANNEL_DATA_HEADER_LEN + len.div_ceil(4) * 4),
        _ => Err(io_err(
            "stream desynchronised: frame is neither STUN nor ChannelData",
        )),
    }
}

#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
