use std::net::{SocketAddr, IpAddr};
use crate::udp_traversal::linear::{SingleUDPHolePuncher, RelativeNodeType};
use crate::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use crate::reliable_conn::ReliableOrderedConnectionToTarget;
use crate::nat_identification::NatType;
use std::str::FromStr;
use async_ip::IpAddressInfo;
use crate::udp_traversal::hole_punched_udp_socket_addr::HolePunchedUdpSocket;
use std::pin::Pin;
use futures::{Future, StreamExt};
use std::task::{Context, Poll};
use futures::stream::FuturesUnordered;
use crate::udp_traversal::NatTraversalMethod;
use serde::{Serialize, Deserialize};

/// Punches a hole using IPv4/6 addrs. IPv6 is more traversal-friendly since IP-translation between external and internal is not needed (unless the NAT admins are evil)
pub(crate) struct DualStackUdpHolePuncher {
    // the key is the local bind addr
    future: Pin<Box<dyn Future<Output=Result<HolePunchedUdpSocket, anyhow::Error>>>>,
}

#[derive(Serialize, Deserialize)]
struct DualStackCandidate {
    bind_addr: SocketAddr
}

impl DualStackUdpHolePuncher {
    #[allow(unused_results)]
    /// `peer_internal_port`: Required for determining the internal socket addr
    pub fn new<T: ReliableOrderedConnectionToTarget + 'static>(relative_node_type: RelativeNodeType, encrypted_config_container: EncryptedConfigContainer, conn: T, peer_nat: NatType, peer_internal_port: u16) -> Result<Self, anyhow::Error> {
        let peer_ip_info = peer_nat.ip_addr_info().ok_or_else(|| anyhow::Error::msg("Peer IP info not loaded"))?;
        let mut hole_punchers = Vec::new();

        let bind_addr_0 = conn.local_addr()?;
        let peer_external_addr_0 = conn.peer_addr()?;

        let peer_internal_addr_0 = SocketAddr::new(peer_ip_info.internal_ipv4, peer_internal_port);

        let (bind_addr_1, peer_external_addr_1, peer_internal_addr_1) = invert(bind_addr_0, peer_external_addr_0, peer_internal_addr_0, peer_ip_info)?;

        // As long as there is translation, we will can attempt dual ipv4/6 hole-punching. This requires that the peer has an IPv6 address
        if peer_external_addr_1 != peer_external_addr_0 && peer_internal_addr_1 != peer_external_addr_0 {
            let hole_puncher1 = SingleUDPHolePuncher::new(relative_node_type, encrypted_config_container.clone(), bind_addr_1, peer_external_addr_1, peer_internal_addr_1)?;
            hole_punchers.push(hole_puncher1);
        }

        let hole_puncher0 = SingleUDPHolePuncher::new(relative_node_type, encrypted_config_container, bind_addr_0, peer_external_addr_0, peer_internal_addr_0)?;

        hole_punchers.push(hole_puncher0);

        Ok(Self { future: Box::pin(drive(hole_punchers, conn)) })
    }
}

impl Future for DualStackUdpHolePuncher {
    type Output = Result<HolePunchedUdpSocket, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

async fn drive<T: ReliableOrderedConnectionToTarget + 'static>(hole_punchers: Vec<SingleUDPHolePuncher>, ref conn: T) -> Result<HolePunchedUdpSocket, anyhow::Error> {
    let mut futures = FuturesUnordered::new();
    for mut hole_puncher in hole_punchers {
        futures.push(async move {
            let res = hole_puncher.try_method(NatTraversalMethod::Method3).await;
            (res, hole_puncher)
        });
    }

    //let mut map = HashMap::new();
    let mut adjacent_completion_id = None;

    while let Some((res, hole_puncher)) = futures.next().await {
        match res {
            Ok(socket) => {
                // the candidate that just finished locally may be what we're waiting for
                if let Some(ref adjacent_candidate) = adjacent_completion_id {
                    if hole_puncher.get_bind_addr() == *adjacent_candidate {
                        log::info!("Returning the socket which the adjacent node previously signalled as a success");
                        return Ok(socket)
                    }
                }

                // first, alert the other side
                conn.send_to_peer(&bincode2::serialize(&DualStackCandidate{ bind_addr: socket.addr.remote_internal_bind_addr }).unwrap()).await?;
                // we will wait until the opposite side sends a candidate
                let adjacent_candidate: DualStackCandidate = bincode2::deserialize(&conn.recv().await?)?;
                log::info!("Adjacent node signalled completion of hole-punch process w/ {:?}", adjacent_candidate.bind_addr);
                if hole_puncher.get_bind_addr() == adjacent_candidate.bind_addr {
                    log::info!("The completed hole-punch subroutine locally was what the adjacent node expected");
                    return Ok(socket);
                } else {
                    log::info!("The locally-completed hole-punched socket is not what the adjacent node signalled. Will discard and keep looping");
                    // this means the local candidate has yet to confirm what the adjacent node has selected. Keep looping, and discard this hole-punch success
                    adjacent_completion_id = Some(adjacent_candidate.bind_addr); // we will wait for the local endpoint to confirm
                    //map.insert(hole_puncher.get_bind_addr(), socket);
                }
            }

            Err(err) => {
                log::warn!("Hole-punch for local bind addr {:?} failed: {:?}", hole_puncher.get_bind_addr(), err);
            }
        }
    }

    Err(anyhow::Error::msg("All hole-punchers failed both locally and remotely. Use TURN"))
}

fn invert(bind_addr_0: SocketAddr, peer_external_addr_0: SocketAddr, peer_internal_addr_0: SocketAddr, peer_ip_info: &IpAddressInfo) -> Result<(SocketAddr, SocketAddr, SocketAddr), anyhow::Error> {
    Ok((invert_bind_addr(bind_addr_0)?, maybe_invert_remote_addr(peer_external_addr_0, peer_ip_info)?, maybe_invert_remote_addr(peer_internal_addr_0, peer_ip_info)?))
}

fn invert_bind_addr(addr: SocketAddr) -> Result<SocketAddr, anyhow::Error> {
    if addr.is_ipv4() {
        if addr.ip().is_loopback() {
            Ok(SocketAddr::new(IpAddr::from_str("::1")?, addr.port()))
        } else {
            Ok(SocketAddr::new(IpAddr::from_str("::")?, addr.port()))
        }
    } else {
        if addr.ip().is_loopback() {
            Ok(SocketAddr::new(IpAddr::from_str("127.0.0.1")?, addr.port()))
        } else {
            Ok(SocketAddr::new(IpAddr::from_str("0.0.0.0")?, addr.port()))
        }
    }
}

fn maybe_invert_remote_addr(addr: SocketAddr, peer_ip_info: &IpAddressInfo) -> Result<SocketAddr, anyhow::Error> {
    if addr.is_ipv4() {
        if let Some(ref ipv6) = peer_ip_info.external_ipv6 {
            // we assume port-preservation mapping between ipv4 and ipv6 (no standardization thereof, yet...)
            Ok(SocketAddr::new(*ipv6, addr.port()))
        } else {
            // no ipv6 implies we won't translate the addr
            Ok(addr)
        }
    } else {
        // we assume port-preservation mapping between ipv4 and ipv6
        Ok(SocketAddr::new(peer_ip_info.external_ipv4, addr.port()))
    }
}