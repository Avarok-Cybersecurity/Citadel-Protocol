//! C7: a negotiation frame is bound to the one P2P connection it belongs to (§5.3).
//!
//! Key identity used to be `(cid, version)`, and two connections of the same pair both start at
//! version 0, so a stale connection's packet was tried under the new connection's keys. A sealed
//! frame carries, in the clear and inside its AEAD's associated data, a tag, the connection's id,
//! the ratchet version it was sealed under and the level. A frame from another connection is
//! refused by its header before any key is tried, and no edit of the header survives the AEAD.
//! The lane that carries these bytes is the in-channel `SignalPort` (lane SDK3).

use crate::error::NetworkError;
use citadel_crypt::ratchets::Ratchet;
use citadel_negotiation::frame::{decode, encode};
use citadel_negotiation::{ConnectionId, Envelope};
use citadel_types::crypto::SecurityLevel;

const TAG: &[u8; 8] = b"cneg/fr1";
const HEADER_LEN: usize = TAG.len() + 16 + 4 + 1;

/// Why a sealed frame was not opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// Too short, or not a negotiation frame.
    Malformed,
    /// Sealed for another connection of the pair.
    OtherConnection,
    /// Sealed under a version this connection's toolset does not hold.
    UnknownVersion(u32),
    /// The AEAD refused it.
    Unauthentic,
    /// It opened but is not an envelope.
    Undecodable,
}

/// Seals `envelope` under `ratchet` at every layer it has, for connection `connection`.
pub fn seal<R: Ratchet>(
    ratchet: &R,
    connection: ConnectionId,
    envelope: &Envelope,
) -> Result<Vec<u8>, NetworkError> {
    let body = encode(envelope).map_err(|err| NetworkError::msg(err.0))?;
    let top = ratchet.message_ratchet_count().saturating_sub(1);
    let level = SecurityLevel::from(u8::try_from(top).unwrap_or(u8::MAX));
    let mut packet = Vec::with_capacity(HEADER_LEN + body.len() + 64);
    packet.extend_from_slice(TAG);
    packet.extend_from_slice(&connection.0.to_be_bytes());
    packet.extend_from_slice(&ratchet.version().to_be_bytes());
    packet.push(level.value());
    packet.extend_from_slice(&body);
    ratchet.protect_message_packet(Some(level), HEADER_LEN, &mut packet)?;
    Ok(packet)
}

/// Opens a frame sealed for `connection`, under the version its header names (never another).
pub fn open<R: Ratchet>(
    version_lookup: impl FnOnce(u32) -> Option<R>,
    connection: ConnectionId,
    bytes: &[u8],
) -> Result<Envelope, OpenError> {
    if bytes.len() < HEADER_LEN || &bytes[..TAG.len()] != TAG {
        return Err(OpenError::Malformed);
    }
    let (header, body) = bytes.split_at(HEADER_LEN);
    let id = u128::from_be_bytes(header[8..24].try_into().map_err(|_| OpenError::Malformed)?);
    if id != connection.0 {
        return Err(OpenError::OtherConnection);
    }
    let version = u32::from_be_bytes(
        header[24..28]
            .try_into()
            .map_err(|_| OpenError::Malformed)?,
    );
    let level = SecurityLevel::from(header[28]);
    let ratchet = version_lookup(version).ok_or(OpenError::UnknownVersion(version))?;
    let mut body = bytes::BytesMut::from(body);
    ratchet
        .validate_message_packet_in_place_split(Some(level), header, &mut body)
        .map_err(|_| OpenError::Unauthentic)?;
    decode(&body).map_err(|_| OpenError::Undecodable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
    use citadel_crypt::prelude::ConstructorOpts;
    use citadel_crypt::ratchets::stacked::StackedRatchet;
    use citadel_negotiation::frame::Frame;
    use citadel_negotiation::{Epoch, SettingId};

    type Constructor = <StackedRatchet as Ratchet>::Constructor;

    /// Two ends of one ratchet version, as a key exchange leaves them.
    fn ends(version: u32) -> (StackedRatchet, StackedRatchet) {
        let opts = ConstructorOpts::new_vec_init(
            crate::proto::misc::session_security_settings::DEFAULT_SESSION_CRYPTO_PARAMS,
            SecurityLevel::Reinforced,
        );
        let psks: &[&[u8]] = &[b"psk"];
        let mut alice = Constructor::new_alice(opts.clone(), 10, version).unwrap();
        let mut bob = Constructor::new_bob(20, opts, alice.stage0_alice().unwrap(), psks).unwrap();
        alice.stage1_alice(bob.stage0_bob().unwrap(), psks).unwrap();
        (alice.finish().unwrap(), bob.finish().unwrap())
    }

    fn envelope() -> Envelope {
        Envelope {
            setting: SettingId::KEY_PROFILE,
            n: 3,
            frame: Frame::Retire { epoch: Epoch(1) },
        }
    }

    const THIS: ConnectionId = ConnectionId(0xA11CE);
    const OTHER: ConnectionId = ConnectionId(0xB0B);

    #[test]
    fn a_frame_opens_on_its_own_connection() {
        let (alice, bob) = ends(0);
        let sealed = seal(&alice, THIS, &envelope()).unwrap();
        assert_eq!(open(|_| Some(bob), THIS, &sealed), Ok(envelope()));
    }

    #[test]
    fn a_frame_from_another_connection_of_the_pair_is_refused_before_any_key() {
        let (alice, _) = ends(0);
        let sealed = seal(&alice, OTHER, &envelope()).unwrap();
        let tried = std::cell::Cell::new(false);
        let result = open::<StackedRatchet>(
            |_| {
                tried.set(true);
                None
            },
            THIS,
            &sealed,
        );
        assert_eq!(result, Err(OpenError::OtherConnection));
        assert!(
            !tried.get(),
            "no key is tried for another connection's frame"
        );
    }

    #[test]
    fn the_connection_id_is_authenticated() {
        let (alice, bob) = ends(0);
        let mut sealed = seal(&alice, OTHER, &envelope()).unwrap();
        sealed[8..24].copy_from_slice(&THIS.0.to_be_bytes());
        assert_eq!(
            open(|_| Some(bob), THIS, &sealed),
            Err(OpenError::Unauthentic)
        );
    }

    #[test]
    fn the_same_version_of_another_connection_does_not_open_it() {
        let (alice, _) = ends(0);
        let (_, stranger) = ends(0);
        let sealed = seal(&alice, THIS, &envelope()).unwrap();
        assert_eq!(
            open(|_| Some(stranger), THIS, &sealed),
            Err(OpenError::Unauthentic)
        );
    }

    #[test]
    fn a_frame_opens_only_under_the_version_it_names() {
        let (alice, bob) = ends(4);
        let sealed = seal(&alice, THIS, &envelope()).unwrap();
        let asked = std::cell::Cell::new(None);
        let _ = open(
            |version| {
                asked.set(Some(version));
                Some(bob)
            },
            THIS,
            &sealed,
        );
        assert_eq!(asked.get(), Some(4));
    }
}
