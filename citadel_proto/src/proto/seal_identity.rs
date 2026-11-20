//! A packet is accepted only under the session it was sealed for.
//!
//! Every packet's header is the associated data of its AEAD. A server authenticates the header of
//! each packet on an admitted session as naming that session's own CID: it writes the CID it
//! authenticated into the header before any AEAD check, so the associated data it checks is
//! fixed by the session, not by the sender. A packet sealed over a header that names any other
//! CID then fails authentication, and every handler after it reads the CID the session was
//! authenticated as. A relayed packet is forwarded as from the same CID.
//!
//! An honest node of any protocol version names its own session in every header it seals, so its
//! packets are unchanged by this and need no version gate.

use crate::proto::packet::HdpHeader;
use zerocopy::Ref;

/// Writes the session's authenticated CID into `packet`'s header. It applies only on a server,
/// once the session is admitted (`session_cid` is set only by a successful connect).
pub(crate) fn bind_to_session(is_server: bool, session_cid: Option<u64>, packet: &mut [u8]) {
    let (true, Some(cid)) = (is_server, session_cid) else {
        return;
    };
    if let Some((mut header, _)) = Ref::<_, HdpHeader>::new_from_prefix(packet) {
        header.session_cid.set(cid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::packet_crafter::peer_cmd::craft_peer_signal;
    use crate::proto::peer::peer_layer::PeerSignal;
    use crate::proto::remote::Ticket;
    use crate::proto::validation::aead::validate_custom;
    use citadel_crypt::endpoint_crypto_container::EndpointRatchetConstructor;
    use citadel_crypt::prelude::ConstructorOpts;
    use citadel_crypt::ratchets::stacked::StackedRatchet;
    use citadel_crypt::ratchets::Ratchet;
    use citadel_types::crypto::SecurityLevel;
    use citadel_types::proto::ClientConnectionType;

    type Constructor = <StackedRatchet as Ratchet>::Constructor;

    const CLIENT: u64 = 10;
    const OTHER: u64 = 77;

    /// One C2S session's keys: the client's end seals as `sealed_as`, the server's end opens.
    fn session_keys(sealed_as: u64) -> (StackedRatchet, StackedRatchet) {
        let opts = ConstructorOpts::new_vec_init(
            crate::proto::misc::session_security_settings::DEFAULT_SESSION_CRYPTO_PARAMS,
            SecurityLevel::Standard,
        );
        let psks: &[&[u8]] = &[b"session"];
        let mut client = Constructor::new_alice(opts.clone(), CLIENT, 0).unwrap();
        let mut server =
            Constructor::new_bob(CLIENT, opts, client.stage0_alice().unwrap(), psks).unwrap();
        client
            .stage1_alice(server.stage0_bob().unwrap(), psks)
            .unwrap();
        (
            client.finish_with_custom_cid(sealed_as).unwrap(),
            server.finish().unwrap(),
        )
    }

    fn sealed_signal(client: &StackedRatchet) -> bytes::BytesMut {
        let signal = PeerSignal::GetMutuals {
            v_conn_type: ClientConnectionType::Server {
                session_cid: client.get_cid(),
            },
            response: None,
        };
        craft_peer_signal(client, signal, Ticket(1), 0, SecurityLevel::Standard).unwrap()
    }

    /// What the server does with a packet: bind it to the session, then open it.
    fn server_opens(server: &StackedRatchet, mut packet: bytes::BytesMut) -> Option<u64> {
        bind_to_session(true, Some(CLIENT), &mut packet);
        let header = packet.split_to(crate::constants::HDP_HEADER_BYTE_LEN);
        validate_custom(server, &header, packet).map(|(header, _)| header.session_cid.get())
    }

    #[test]
    fn a_packet_sealed_for_its_own_session_opens() {
        let (client, server) = session_keys(CLIENT);
        assert_eq!(server_opens(&server, sealed_signal(&client)), Some(CLIENT));
    }

    #[test]
    fn a_packet_sealed_naming_another_cid_is_refused_by_the_aead() {
        let (client, server) = session_keys(OTHER);
        let packet = sealed_signal(&client);
        assert_eq!(header_cid(&packet), OTHER);
        assert_eq!(server_opens(&server, packet), None);
    }

    #[test]
    fn a_packet_relabelled_after_sealing_is_read_as_the_session_it_was_sealed_for() {
        let (client, server) = session_keys(CLIENT);
        let mut packet = sealed_signal(&client);
        Ref::<_, HdpHeader>::new_from_prefix(&mut packet[..])
            .unwrap()
            .0
            .session_cid
            .set(OTHER);
        assert_eq!(server_opens(&server, packet), Some(CLIENT));
    }

    #[test]
    fn an_honest_packet_of_any_version_is_unchanged() {
        let (client, _) = session_keys(CLIENT);
        let packet = sealed_signal(&client);
        let mut bound = packet.clone();
        bind_to_session(true, Some(CLIENT), &mut bound);
        assert_eq!(bound, packet);
    }

    #[test]
    fn a_client_and_an_unadmitted_session_leave_the_header_alone() {
        let (client, _) = session_keys(OTHER);
        let packet = sealed_signal(&client);
        for (is_server, session_cid) in [(false, Some(CLIENT)), (true, None)] {
            let mut untouched = packet.clone();
            bind_to_session(is_server, session_cid, &mut untouched);
            assert_eq!(untouched, packet);
        }
    }

    fn header_cid(packet: &[u8]) -> u64 {
        Ref::<_, HdpHeader>::new_from_prefix(packet)
            .unwrap()
            .0
            .session_cid
            .get()
    }
}
