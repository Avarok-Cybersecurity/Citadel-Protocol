//! P2P over a TURN relay, for peers the hole punch cannot connect.
//!
//! Roles are fixed by CID so both peers agree without negotiating: the lower CID allocates a
//! relay and is the QUIC listener (matching `insert_direct_p2p_connection`'s tie-breaker, which
//! keeps the connection whose higher-CID peer is the client); the higher CID dials the relayed
//! address from a plain UDP socket.
//!
//! Signalling rides the peers' netbeam endpoint — the hole-punch compat stream, end-to-end
//! encrypted with the P2P ratchet — so the Citadel server never sees relay addresses or probe
//! nonces, and no PeerSignal/wire format changes. A peer that predates this module never answers;
//! the attempt times out and the connection stays server-relayed.
//!
//! 1. allocator → dialer: `Offer { relayed, nonce }` (or `Unavailable`)
//! 2. dialer → allocator: `DialerReady { candidates }` — IPs the relay may see the dialer from
//! 3. allocator installs permissions for them (plus the server-observed IP), → `PermissionsReady`
//! 4. dialer probes the relayed address with the nonce; the allocator learns the dialer's exact
//!    address from the first matching probe, binds a channel to it and acks through it
//! 5. dialer → `ProbeAcked`; allocator starts its QUIC listener → `ListenerReady`; dialer connects

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::net::UdpSocket;
use citadel_io::Rng;
use citadel_types::proto::{SessionSecuritySettings, UdpMode};
use citadel_wire::exports::tokio_rustls::rustls;
use citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr;
use citadel_wire::udp_traversal::turn_relay::TurnRelayConfig;
use netbeam::reliable_conn::ReliableOrderedStreamToTargetExt;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::subscription::Subscribable;
use serde::{Deserialize, Serialize};

use crate::proto::misc::dual_rwlock::DualRwLock;
use crate::proto::misc::native_connect::{p2p_connect_relayed, p2p_listener_from_relay};
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::peer::p2p_conn_handler::generic_error;
use crate::proto::peer::p2p_conn_handler::native_p2p::{handle_p2p_stream, p2p_conn_handler};
use crate::proto::peer::p2p_path::P2pPath;
use crate::proto::peer::peer_crypt::PeerNatInfo;
use crate::proto::peer::turn_rendezvous::{
    allocate_first_usable, await_probe, dialer_candidates, permission_candidates,
    probe_until_acked, unspecified_like,
};
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use crate::proto::state_container::VirtualConnectionType;

/// Upper bound on one relay attempt (allocation, signalling, probing and the QUIC handshake).
pub(crate) const RELAY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Serialize, Deserialize, Debug)]
enum RelaySignal {
    Offer {
        relayed: SocketAddr,
        nonce: [u8; 16],
    },
    Unavailable(String),
    DialerReady {
        candidates: Vec<IpAddr>,
    },
    PermissionsReady,
    ProbeAcked,
    ListenerReady,
}

/// Connects the two peers through a TURN relay and installs the result as their direct P2P
/// connection (path [`P2pPath::Turn`]); the UDP channel is then fulfilled over it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn establish_relayed_p2p<R: Ratchet, T: PlatformOps>(
    app: &NetworkEndpoint,
    config: TurnRelayConfig,
    session: CitadelSession<R, T>,
    session_cid: DualRwLock<Option<u64>>,
    peer_nat_info: &PeerNatInfo,
    v_conn: VirtualConnectionType,
    ticket: Ticket,
    udp_mode: UdpMode,
    session_security_settings: SessionSecuritySettings,
    tls: Arc<rustls::ClientConfig>,
) -> io::Result<()> {
    let local_cid = session_cid
        .get()
        .ok_or_else(|| generic_error("session CID not loaded"))?;
    let stream = app.initiate_subscription().await.map_err(generic_error)?;
    let recv = || async {
        stream
            .recv_serialized::<RelaySignal>()
            .await
            .map_err(generic_error)
    };
    let hole_punched_like = |remote: SocketAddr| TargettedSocketAddr::new_invariant(remote);

    if local_cid < v_conn.get_target_cid() {
        let allocation = match allocate_first_usable(&config, tls).await {
            Ok(a) => a,
            Err(err) => {
                let _ = stream
                    .send_serialized(RelaySignal::Unavailable(err.to_string()))
                    .await;
                return Err(err);
            }
        };
        let relayed = allocation.relayed_addr();
        let mut nonce = [0u8; 16];
        citadel_io::thread_rng().fill(&mut nonce);
        stream
            .send_serialized(RelaySignal::Offer { relayed, nonce })
            .await?;
        let RelaySignal::DialerReady { candidates } = recv().await? else {
            return Err(generic_error("expected DialerReady"));
        };
        let server_seen = peer_nat_info.peer_remote_addr_visible_from_server.ip();
        let ips = permission_candidates(relayed, candidates.into_iter().chain([server_seen]));
        if ips.is_empty() {
            return Err(generic_error("no dialer address of the relay's family"));
        }
        allocation.create_permissions(&ips).await?;
        stream
            .send_serialized(RelaySignal::PermissionsReady)
            .await?;
        let acked = async {
            match recv().await? {
                RelaySignal::ProbeAcked => Ok(()),
                other => Err(generic_error(format!("expected ProbeAcked, got {other:?}"))),
            }
        };
        let dialer = await_probe(&allocation, &nonce, acked).await?;
        let listener = p2p_listener_from_relay(Arc::new(allocation))?;
        stream.send_serialized(RelaySignal::ListenerReady).await?;
        log::info!(target: "citadel", "[TURN] listening on relayed {relayed} for dialer {dialer}");
        p2p_conn_handler(
            listener,
            session,
            dialer,
            v_conn,
            hole_punched_like(dialer),
            ticket,
            udp_mode,
            session_security_settings,
            P2pPath::Turn,
        )
        .await
        .map_err(|err| generic_error(err.into_string()))
    } else {
        let (relayed, nonce) = match recv().await? {
            RelaySignal::Offer { relayed, nonce } => (relayed, nonce),
            RelaySignal::Unavailable(why) => {
                return Err(generic_error(format!("peer has no relay: {why}")))
            }
            other => return Err(generic_error(format!("expected Offer, got {other:?}"))),
        };
        let socket = UdpSocket::bind(unspecified_like(relayed)).await?;
        let candidates = dialer_candidates(&socket, relayed, &config).await;
        stream
            .send_serialized(RelaySignal::DialerReady { candidates })
            .await?;
        let RelaySignal::PermissionsReady = recv().await? else {
            return Err(generic_error("expected PermissionsReady"));
        };
        probe_until_acked(&socket, relayed, &nonce).await?;
        stream.send_serialized(RelaySignal::ProbeAcked).await?;
        let RelaySignal::ListenerReady = recv().await? else {
            return Err(generic_error("expected ListenerReady"));
        };
        let p2p_stream =
            p2p_connect_relayed(socket, relayed, peer_nat_info.tls_domain.clone(), tls, None)
                .await?;
        log::info!(target: "citadel", "[TURN] connected to peer via relayed {relayed}");
        let kernel_tx = session.kernel_tx.clone();
        handle_p2p_stream(
            p2p_stream,
            session_cid,
            session,
            kernel_tx,
            false,
            v_conn,
            hole_punched_like(relayed),
            ticket,
            udp_mode,
            session_security_settings,
            P2pPath::Turn,
        )
    }
}
