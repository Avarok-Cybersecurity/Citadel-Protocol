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
//!
//! Relay-to-relay: a dialer that cannot send UDP (no UDP TURN server in its config, none answers
//! STUN, or its plain-UDP probes go unanswered) allocates its own relay — over TCP/TLS first — and
//! sends `DialerRelayed { relayed }` in place of `DialerReady` / `ProbeAcked`. Each side then
//! permits the other's relayed IP (public, so the 403 providers give private peers does not
//! apply), binds a channel to it, and the probe/QUIC run through both allocations. The path is
//! still `Turn`, with `relayed_both` set so accounting sees the double egress.

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
use netbeam::reliable_conn::ReliableOrderedStreamToTarget;
use netbeam::reliable_conn::ReliableOrderedStreamToTargetExt;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::subscription::Subscribable;
use serde::{Deserialize, Serialize};

use crate::proto::misc::dual_rwlock::DualRwLock;
use crate::proto::misc::native_connect::{
    p2p_connect_relayed, p2p_listener_from_relay, RelayDialerSocket,
};
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::peer::p2p_conn_handler::generic_error;
use crate::proto::peer::p2p_conn_handler::native_p2p::{handle_p2p_stream, p2p_conn_handler};
use crate::proto::peer::p2p_path::P2pRoute;
use crate::proto::peer::peer_crypt::PeerNatInfo;
use crate::proto::peer::turn_rendezvous::{
    allocate_first_usable, await_probe, dialer_candidates, install_permissions,
    permission_candidates, probe_until_acked, unspecified_like, ProbeLeg, PROBE_TIMEOUT,
    UDP_PROBE_TIMEOUT,
};
use crate::proto::remote::Ticket;
use crate::proto::session::CitadelSession;
use crate::proto::state_container::VirtualConnectionType;
use citadel_wire::udp_traversal::turn_relay::TurnAllocation;

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
    /// The dialer relays through its own allocation at `relayed` (relay-to-relay).
    DialerRelayed {
        relayed: SocketAddr,
    },
}

async fn recv<S: ReliableOrderedStreamToTarget>(stream: &S) -> io::Result<RelaySignal> {
    stream
        .recv_serialized::<RelaySignal>()
        .await
        .map_err(generic_error)
}

fn unexpected(want: &str, got: RelaySignal) -> io::Error {
    generic_error(format!("expected {want}, got {got:?}"))
}

/// Permits and binds a channel to the other peer's relayed address on `allocation`.
async fn face_peer_relay(allocation: &TurnAllocation, peer_relayed: SocketAddr) -> io::Result<()> {
    allocation.create_permissions(&[peer_relayed.ip()]).await?;
    allocation.bind_channel(peer_relayed).await.map(|_| ())
}

/// Connects the two peers through TURN and installs the result as their direct P2P connection
/// (path [`P2pPath::Turn`](crate::proto::peer::p2p_path::P2pPath::Turn)); the UDP channel is then
/// fulfilled over it.
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
    let hole_punched_like = TargettedSocketAddr::new_invariant;

    if local_cid < v_conn.get_target_cid() {
        let allocation = match allocate_first_usable(&config, tls, false).await {
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
        let mut peer_relayed = match recv(&stream).await? {
            RelaySignal::DialerReady { candidates } => {
                let server_seen = peer_nat_info.peer_remote_addr_visible_from_server.ip();
                let ips =
                    permission_candidates(relayed, candidates.into_iter().chain([server_seen]));
                install_permissions(&allocation, &ips).await?;
                None
            }
            RelaySignal::DialerRelayed { relayed } => Some(relayed),
            other => return Err(unexpected("DialerReady or DialerRelayed", other)),
        };
        if let Some(peer) = peer_relayed {
            face_peer_relay(&allocation, peer).await?;
        }
        stream
            .send_serialized(RelaySignal::PermissionsReady)
            .await?;
        let dialer = loop {
            let (probed, signal) = await_probe(&allocation, &nonce, recv(&stream)).await?;
            match signal {
                RelaySignal::ProbeAcked => {
                    break probed.ok_or_else(|| generic_error("ProbeAcked before any probe"))?
                }
                // Its plain-UDP probes failed; it fell back to its own relay.
                RelaySignal::DialerRelayed { relayed } if peer_relayed.is_none() => {
                    face_peer_relay(&allocation, relayed).await?;
                    peer_relayed = Some(relayed);
                    stream
                        .send_serialized(RelaySignal::PermissionsReady)
                        .await?;
                }
                other => return Err(unexpected("ProbeAcked", other)),
            }
        };
        let route = P2pRoute::Turn {
            relayed_both: peer_relayed.is_some(),
        };
        let listener = p2p_listener_from_relay(Arc::new(allocation))?;
        stream.send_serialized(RelaySignal::ListenerReady).await?;
        log::info!(target: "citadel", "[TURN] listening on relayed {relayed} for dialer {dialer} ({route:?})");
        p2p_conn_handler(
            listener,
            session,
            dialer,
            v_conn,
            hole_punched_like(dialer),
            ticket,
            udp_mode,
            session_security_settings,
            route,
        )
        .await
        .map_err(|err| generic_error(err.into_string()))
    } else {
        let (relayed, nonce) = match recv(&stream).await? {
            RelaySignal::Offer { relayed, nonce } => (relayed, nonce),
            RelaySignal::Unavailable(why) => {
                return Err(generic_error(format!("peer has no relay: {why}")))
            }
            other => return Err(unexpected("Offer", other)),
        };
        let socket = UdpSocket::bind(unspecified_like(relayed)).await?;
        let (candidates, udp_works) = dialer_candidates(&socket, relayed, &config).await;
        let mut own_relay = None;
        if udp_works {
            stream
                .send_serialized(RelaySignal::DialerReady { candidates })
                .await?;
            expect_permissions(&stream).await?;
            let leg = ProbeLeg::Udp(&socket);
            if let Err(err) = probe_until_acked(leg, relayed, &nonce, UDP_PROBE_TIMEOUT).await {
                log::warn!(target: "citadel", "[TURN] plain UDP to the relay failed ({err}); relaying through our own allocation");
                own_relay = Some(own_relay_facing(&stream, &config, tls.clone(), relayed).await?);
            }
        } else {
            log::info!(target: "citadel", "[TURN] UDP unavailable here; relaying through our own allocation");
            own_relay = Some(own_relay_facing(&stream, &config, tls.clone(), relayed).await?);
        }
        let (dialer_socket, relayed_both) = match own_relay {
            Some(allocation) => {
                let leg = ProbeLeg::OwnRelay(&allocation);
                probe_until_acked(leg, relayed, &nonce, PROBE_TIMEOUT).await?;
                (RelayDialerSocket::OwnRelay(Arc::new(allocation)), true)
            }
            None => (RelayDialerSocket::Udp(socket), false),
        };
        stream.send_serialized(RelaySignal::ProbeAcked).await?;
        match recv(&stream).await? {
            RelaySignal::ListenerReady => {}
            other => return Err(unexpected("ListenerReady", other)),
        }
        let p2p_stream = p2p_connect_relayed(
            dialer_socket,
            relayed,
            peer_nat_info.tls_domain.clone(),
            tls,
            None,
        )
        .await?;
        let route = P2pRoute::Turn { relayed_both };
        log::info!(target: "citadel", "[TURN] connected to peer via relayed {relayed} ({route:?})");
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
            route,
        )
    }
}

async fn expect_permissions<S: ReliableOrderedStreamToTarget>(stream: &S) -> io::Result<()> {
    match recv(stream).await? {
        RelaySignal::PermissionsReady => Ok(()),
        other => Err(unexpected("PermissionsReady", other)),
    }
}

/// Dialer: allocates its own relay (stream transports first: its UDP is suspect), faces the
/// allocator's relayed address, and tells the allocator where it is.
async fn own_relay_facing<S: ReliableOrderedStreamToTarget>(
    stream: &S,
    config: &TurnRelayConfig,
    tls: Arc<rustls::ClientConfig>,
    peer_relayed: SocketAddr,
) -> io::Result<TurnAllocation> {
    let allocation = allocate_first_usable(config, tls, true).await?;
    face_peer_relay(&allocation, peer_relayed).await?;
    stream
        .send_serialized(RelaySignal::DialerRelayed {
            relayed: allocation.relayed_addr(),
        })
        .await?;
    expect_permissions(stream).await?;
    Ok(allocation)
}
