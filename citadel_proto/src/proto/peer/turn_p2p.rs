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

use citadel_io::tokio::net::UdpSocket;
use citadel_io::Rng;
use citadel_wire::exports::tokio_rustls::rustls;
use citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr;
use citadel_wire::udp_traversal::turn_relay::TurnRelayConfig;
use netbeam::reliable_conn::ReliableOrderedStreamToTarget;
use netbeam::reliable_conn::ReliableOrderedStreamToTargetExt;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::subscription::Subscribable;
use serde::{Deserialize, Serialize};

use crate::proto::link::p2p::direct::accept_one;
pub(crate) use crate::proto::link::p2p::turn::RelayedPath;
use crate::proto::misc::native_connect::{
    p2p_connect_relayed, p2p_listener_from_relay, RelayDialerSocket,
};
use crate::proto::peer::p2p_conn_handler::generic_error;
use crate::proto::peer::p2p_outcome::{AtStage, StageError, StageFailure};
use crate::proto::peer::p2p_path::P2pRoute;
use crate::proto::peer::peer_crypt::PeerNatInfo;
use crate::proto::peer::turn_rendezvous::{
    allocate_first_usable, await_probe, dialer_candidates, install_permissions,
    permission_candidates, probe_until_acked, unspecified_like, ProbeLeg, PROBE_TIMEOUT,
    UDP_PROBE_TIMEOUT,
};
use citadel_wire::udp_traversal::turn_relay::TurnAllocation;

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

/// Path: the TURN stage of an attempt, up to the QUIC connection through the relay (the seal and
/// the delivery are the caller's). `local_cid` and `peer_cid` fix the roles.
pub(crate) async fn open_relayed_path(
    app: &NetworkEndpoint,
    config: &TurnRelayConfig,
    local_cid: u64,
    peer_cid: u64,
    peer_nat_info: &PeerNatInfo,
    tls: Arc<rustls::ClientConfig>,
) -> Result<RelayedPath, StageError> {
    use StageFailure::{
        AllocationFailed, HandshakeFailed, LocalSocket, PeerUnavailable, PermissionFailed,
        ProbeFailed, Signalling,
    };
    let config = config.clone();
    let signalling = app.on(crate::proto::peer::coordination::TURN_SIGNALLING);
    let stream = signalling.initiate_subscription().await.at(Signalling)?;
    let hole_punched_like = TargettedSocketAddr::new_invariant;

    if crate::proto::peer::pair_role::leads(local_cid, peer_cid) {
        let allocation = match allocate_first_usable(&config, tls, false).await {
            Ok(a) => a,
            Err(err) => {
                let _ = stream
                    .send_serialized(RelaySignal::Unavailable(err.to_string()))
                    .await;
                return Err(err).at(AllocationFailed);
            }
        };
        let relayed = allocation.relayed_addr();
        let mut nonce = [0u8; 16];
        citadel_io::thread_rng().fill(&mut nonce);
        stream
            .send_serialized(RelaySignal::Offer { relayed, nonce })
            .await
            .at(Signalling)?;
        let mut peer_relayed = match recv(&stream).await.at(Signalling)? {
            RelaySignal::DialerReady { candidates } => {
                let server_seen = peer_nat_info.peer_remote_addr_visible_from_server.ip();
                let ips =
                    permission_candidates(relayed, candidates.into_iter().chain([server_seen]));
                install_permissions(&allocation, &ips)
                    .await
                    .at(PermissionFailed)?;
                None
            }
            RelaySignal::DialerRelayed { relayed } => Some(relayed),
            other => return Err(unexpected("DialerReady or DialerRelayed", other)).at(Signalling),
        };
        if let Some(peer) = peer_relayed {
            face_peer_relay(&allocation, peer)
                .await
                .at(PermissionFailed)?;
        }
        stream
            .send_serialized(RelaySignal::PermissionsReady)
            .await
            .at(Signalling)?;
        let dialer = loop {
            let (probed, signal) = await_probe(&allocation, &nonce, recv(&stream))
                .await
                .at(ProbeFailed)?;
            match signal {
                RelaySignal::ProbeAcked => {
                    break probed.ok_or_else(|| {
                        StageError::new(ProbeFailed, "ProbeAcked before any probe")
                    })?
                }
                // Its plain-UDP probes failed; it fell back to its own relay.
                RelaySignal::DialerRelayed { relayed } if peer_relayed.is_none() => {
                    face_peer_relay(&allocation, relayed)
                        .await
                        .at(PermissionFailed)?;
                    peer_relayed = Some(relayed);
                    stream
                        .send_serialized(RelaySignal::PermissionsReady)
                        .await
                        .at(Signalling)?;
                }
                other => return Err(unexpected("ProbeAcked", other)).at(Signalling),
            }
        };
        let route = P2pRoute::Turn {
            relayed_both: peer_relayed.is_some(),
        };
        let listener = p2p_listener_from_relay(Arc::new(allocation)).at(LocalSocket)?;
        stream
            .send_serialized(RelaySignal::ListenerReady)
            .await
            .at(Signalling)?;
        log::info!(target: "citadel", "[TURN] listening on relayed {relayed} for dialer {dialer} ({route:?})");
        let stream = accept_one(listener).await?;
        Ok(RelayedPath {
            stream,
            addr: hole_punched_like(dialer),
            from_listener: true,
            route,
        })
    } else {
        let (relayed, nonce) = match recv(&stream).await.at(Signalling)? {
            RelaySignal::Offer { relayed, nonce } => (relayed, nonce),
            RelaySignal::Unavailable(why) => {
                return Err(StageError::new(
                    PeerUnavailable,
                    format!("peer has no relay: {why}"),
                ))
            }
            other => return Err(unexpected("Offer", other)).at(Signalling),
        };
        let socket = UdpSocket::bind(unspecified_like(relayed))
            .await
            .at(LocalSocket)?;
        let (candidates, udp_works) = dialer_candidates(&socket, relayed, &config).await;
        let mut own_relay = None;
        if udp_works {
            stream
                .send_serialized(RelaySignal::DialerReady { candidates })
                .await
                .at(Signalling)?;
            expect_permissions(&stream).await.at(Signalling)?;
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
                probe_until_acked(leg, relayed, &nonce, PROBE_TIMEOUT)
                    .await
                    .at(ProbeFailed)?;
                (RelayDialerSocket::OwnRelay(Arc::new(allocation)), true)
            }
            None => (RelayDialerSocket::Udp(socket), false),
        };
        stream
            .send_serialized(RelaySignal::ProbeAcked)
            .await
            .at(Signalling)?;
        match recv(&stream).await.at(Signalling)? {
            RelaySignal::ListenerReady => {}
            other => return Err(unexpected("ListenerReady", other)).at(Signalling),
        }
        let p2p_stream = p2p_connect_relayed(
            dialer_socket,
            relayed,
            peer_nat_info.tls_domain.clone(),
            tls,
            None,
        )
        .await
        .at(HandshakeFailed)?;
        let route = P2pRoute::Turn { relayed_both };
        log::info!(target: "citadel", "[TURN] connected to peer via relayed {relayed} ({route:?})");
        Ok(RelayedPath {
            stream: p2p_stream,
            addr: hole_punched_like(relayed),
            from_listener: false,
            route,
        })
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
) -> Result<TurnAllocation, StageError> {
    let allocation = allocate_first_usable(config, tls, true)
        .await
        .at(StageFailure::AllocationFailed)?;
    face_peer_relay(&allocation, peer_relayed)
        .await
        .at(StageFailure::PermissionFailed)?;
    stream
        .send_serialized(RelaySignal::DialerRelayed {
            relayed: allocation.relayed_addr(),
        })
        .await
        .at(StageFailure::Signalling)?;
    expect_permissions(stream)
        .await
        .at(StageFailure::Signalling)?;
    Ok(allocation)
}
