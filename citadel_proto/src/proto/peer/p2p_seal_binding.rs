//! A P2P connection's keys are derived from the connection they are for.
//!
//! Both peers of a key exchange mix one more pre-shared key into it: the initiator's CID, the
//! responder's CID and the connection's id (the `p2p_connection_id` the initiator draws and the
//! responder echoes; the key-epoch handle names the connection by the same id). Every key of the
//! connection descends from that exchange, rekeys included, since each chains the one before. A
//! packet is therefore accepted only under the connection it was sealed for: sealed for another
//! pair, another connection of the same pair, or by a peer claiming another CID in the exchange,
//! it fails the AEAD under these keys at every version. The CIDs are the ones the server
//! authenticated (`packet_processor::peer::server::sender_binding`).
//!
//! It changes the keys, so both peers must take part or neither: each binds only when the other's
//! key-exchange signal names a version at or above [`IDENTITY_BOUND_SEAL_SINCE`]. With an older
//! or unknown peer, the exchange runs on the session password alone, exactly as before.

use crate::constants::{protocol_version_at_least, IDENTITY_BOUND_SEAL_SINCE};
use crate::proto::remote::Ticket;
use citadel_types::crypto::PreSharedKey;

const TAG: &[u8; 19] = b"citadel/p2p-seal/v1";

/// The connection a P2P exchange builds keys for, as both of its peers name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct P2pSealContext {
    /// The peer that sent the exchange's Stage0.
    pub initiator: u64,
    /// The peer that answered it.
    pub responder: u64,
    pub connection: Ticket,
}

impl P2pSealContext {
    fn as_psk(&self) -> Vec<u8> {
        let mut psk = Vec::with_capacity(TAG.len() + 8 + 8 + 16);
        psk.extend_from_slice(TAG);
        psk.extend_from_slice(&self.initiator.to_be_bytes());
        psk.extend_from_slice(&self.responder.to_be_bytes());
        psk.extend_from_slice(&self.connection.0.to_be_bytes());
        psk
    }
}

/// The pre-shared keys this end runs the exchange with: the session password's, then the
/// connection's context when the peer's protocol version binds it too.
pub(crate) fn exchange_psks(
    session_password: &PreSharedKey,
    context: P2pSealContext,
    peer_protocol_version: Option<u32>,
) -> Vec<Vec<u8>> {
    let mut psks = session_password.as_ref().to_vec();
    if protocol_version_at_least(peer_protocol_version, IDENTITY_BOUND_SEAL_SINCE) {
        psks.push(context.as_psk());
    }
    psks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::PROTOCOL_VERSION;
    use crate::proto::packet_crafter::peer_cmd::craft_peer_signal;
    use crate::proto::peer::peer_layer::PeerSignal;
    use crate::proto::validation::aead::validate_custom;
    use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
    use citadel_crypt::prelude::ConstructorOpts;
    use citadel_crypt::ratchets::stacked::StackedRatchet;
    use citadel_crypt::ratchets::Ratchet;
    use citadel_types::crypto::SecurityLevel;
    use citadel_types::proto::ClientConnectionType;
    use embedded_semver::Semver;

    type Constructor = <StackedRatchet as Ratchet>::Constructor;

    const ALICE: u64 = 10;
    const BOB: u64 = 20;
    const CAROL: u64 = 30;

    fn context(initiator: u64, connection: u128) -> P2pSealContext {
        P2pSealContext {
            initiator,
            responder: BOB,
            connection: Ticket(connection),
        }
    }

    fn new() -> Option<u32> {
        Some(*PROTOCOL_VERSION)
    }

    fn old() -> Option<u32> {
        Some(Semver::new(0, 12, 2).to_u32().unwrap())
    }

    /// One exchange, each end with its own pre-shared keys; `None` if it did not complete.
    fn exchange(alice: &[Vec<u8>], bob: &[Vec<u8>]) -> Option<(StackedRatchet, StackedRatchet)> {
        let opts = ConstructorOpts::new_vec_init(
            crate::proto::misc::session_security_settings::DEFAULT_SESSION_CRYPTO_PARAMS,
            SecurityLevel::Standard,
        );
        let mut a = Constructor::new_alice(opts.clone(), ALICE, 0)?;
        let mut b = Constructor::new_bob(BOB, opts, a.stage0_alice()?, bob)?;
        a.stage1_alice(b.stage0_bob()?, alice).ok()?;
        Some((a.finish_with_custom_cid(ALICE)?, b.finish()?))
    }

    /// Whether a packet Alice seals opens under Bob's end.
    fn opens(ends: Option<(StackedRatchet, StackedRatchet)>) -> bool {
        let Some((alice, bob)) = ends else {
            return false;
        };
        let signal = PeerSignal::GetMutuals {
            v_conn_type: ClientConnectionType::Server { session_cid: ALICE },
            response: None,
        };
        let mut packet =
            craft_peer_signal(&alice, signal, Ticket(1), 0, SecurityLevel::Standard).unwrap();
        let header = packet.split_to(crate::constants::HDP_HEADER_BYTE_LEN);
        validate_custom(&bob, &header, packet).is_some()
    }

    fn password() -> PreSharedKey {
        PreSharedKey::from("pair")
    }

    #[test]
    fn both_ends_of_one_connection_derive_the_same_keys() {
        let psks = exchange_psks(&password(), context(ALICE, 1), new());
        assert!(opens(exchange(&psks, &psks)));
    }

    #[test]
    fn a_packet_is_not_accepted_under_another_connection_of_the_same_pair() {
        let alice = exchange_psks(&password(), context(ALICE, 1), new());
        let bob = exchange_psks(&password(), context(ALICE, 2), new());
        assert!(!opens(exchange(&alice, &bob)));
    }

    #[test]
    fn a_peer_that_claims_another_cid_does_not_share_the_keys() {
        let alice = exchange_psks(&password(), context(CAROL, 1), new());
        let bob = exchange_psks(&password(), context(ALICE, 1), new());
        assert!(!opens(exchange(&alice, &bob)));
    }

    #[test]
    fn with_an_older_peer_the_exchange_runs_on_the_session_password_alone() {
        let bound = exchange_psks(&password(), context(ALICE, 1), old());
        assert_eq!(bound, password().as_ref().to_vec());
        // An older peer derives from the session password only, so the pair still connects.
        let older_peer = password().as_ref().to_vec();
        assert!(opens(exchange(&bound, &older_peer)));
    }

    #[test]
    fn an_unknown_peer_version_does_not_bind() {
        assert_eq!(
            exchange_psks(&password(), context(ALICE, 1), None),
            password().as_ref().to_vec()
        );
    }

    #[test]
    fn binding_is_a_wire_change_both_peers_must_agree_on() {
        let bound = exchange_psks(&password(), context(ALICE, 1), new());
        let older_peer = password().as_ref().to_vec();
        assert!(!opens(exchange(&bound, &older_peer)));
    }
}
