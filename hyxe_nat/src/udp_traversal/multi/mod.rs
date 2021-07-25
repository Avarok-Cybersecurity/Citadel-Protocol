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
use crate::udp_traversal::{NatTraversalMethod, HolePunchID};
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use std::collections::{HashMap, BTreeSet};

/// Punches a hole using IPv4/6 addrs. IPv6 is more traversal-friendly since IP-translation between external and internal is not needed (unless the NAT admins are evil)
///
/// allows the inclusion of a "breadth" variable to allow opening multiple ports for traversing across multiple ports
pub(crate) struct DualStackUdpHolePuncher<'a> {
    // the key is the local bind addr
    future: Pin<Box<dyn Future<Output=Result<HolePunchedUdpSocket, anyhow::Error>> + 'a>>,
}

#[derive(Serialize, Deserialize)]
enum DualStackCandidate {
    SingleHolePunchSuccess(BTreeSet<HolePunchID>),
    ResolveUseAnyOf(BTreeSet<HolePunchID>),
    // Maybe contains an addr that both sides have
    Resolved(Option<HolePunchID>)
}

impl<'a> DualStackUdpHolePuncher<'a> {
    #[allow(unused_results)]
    /// `peer_internal_port`: Required for determining the internal socket addr
    pub fn new<T: ReliableOrderedConnectionToTarget + 'a>(relative_node_type: RelativeNodeType, encrypted_config_container: EncryptedConfigContainer, conn: &'a T, local_nat: &NatType, peer_nat: &NatType, peer_internal_port: u16, breadth: u16) -> Result<Self, anyhow::Error> {
        let mut hole_punchers = Vec::new();
        let ref mut init_unique_id = HolePunchID(0);
        Self::generate_dual_stack_hole_punchers_with_delta(&mut hole_punchers, relative_node_type, encrypted_config_container.clone(), conn, local_nat, peer_nat, peer_internal_port, 0, init_unique_id)?;

        if breadth > 1 {
            for delta in 1..breadth {
                Self::generate_dual_stack_hole_punchers_with_delta(&mut hole_punchers, relative_node_type, encrypted_config_container.clone(), conn, local_nat, peer_nat, peer_internal_port, delta, init_unique_id)?;
            }
        }

        Ok(Self { future: Box::pin(drive(hole_punchers, conn, relative_node_type)) })
    }

    fn generate_dual_stack_hole_punchers_with_delta<T: ReliableOrderedConnectionToTarget + 'a>(hole_punchers: &mut Vec<SingleUDPHolePuncher>, relative_node_type: RelativeNodeType, encrypted_config_container: EncryptedConfigContainer, conn: &'a T, local_nat: &NatType, peer_nat: &NatType, peer_internal_port: u16, delta: u16, unique_id: &mut HolePunchID) -> Result<(), anyhow::Error> {
        let peer_ip_info = peer_nat.ip_addr_info().ok_or_else(|| anyhow::Error::msg("Peer IP info not loaded"))?;
        let local_ip_info = local_nat.ip_addr_info().ok_or_else(|| anyhow::Error::msg("Local IP info not loaded"))?;

        let bind_addr_0 = conn.local_addr()?;
        let peer_external_addr_0 = conn.peer_addr()?;
        let peer_internal_addr_0 = SocketAddr::new(peer_ip_info.internal_ipv4, peer_internal_port);

        let (bind_addr_1, peer_external_addr_1, peer_internal_addr_1) = invert(bind_addr_0, peer_external_addr_0, peer_internal_addr_0, peer_ip_info)?;

        let (bind_addr_0, peer_external_addr_0, peer_internal_addr_0, bind_addr_1, peer_external_addr_1, peer_internal_addr_1) = increment_ports(bind_addr_0, peer_external_addr_0, peer_internal_addr_0, bind_addr_1, peer_external_addr_1, peer_internal_addr_1, delta);

        // As long as there is translation, we will can attempt dual ipv4/6 hole-punching. This requires that the peer has an IPv6 address
        // also, if THIS node has an IPv6 address, then the adjacent node will attempt to connect to it, so in that case, we will need to bind regardless to ipv6 addrs IF the zeroth hole-puncher is not already ipv6
        if (peer_external_addr_1 != peer_external_addr_0 && peer_internal_addr_1 != peer_external_addr_0 && bind_addr_0 != bind_addr_1) || (bind_addr_0.is_ipv4() && local_ip_info.external_ipv6.is_some()) {
            let hole_puncher1 = SingleUDPHolePuncher::new(relative_node_type, encrypted_config_container.clone(), bind_addr_1, peer_external_addr_1, peer_internal_addr_1, unique_id.next())?;
            hole_punchers.push(hole_puncher1);
        }

        let hole_puncher0 = SingleUDPHolePuncher::new(relative_node_type, encrypted_config_container, bind_addr_0, peer_external_addr_0, peer_internal_addr_0, unique_id.next())?;

        hole_punchers.push(hole_puncher0);

        Ok(())
    }
}

impl Future for DualStackUdpHolePuncher<'_> {
    type Output = Result<HolePunchedUdpSocket, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

async fn drive<'a, T: ReliableOrderedConnectionToTarget + 'a>(hole_punchers: Vec<SingleUDPHolePuncher>, conn: &'a T, node_type: RelativeNodeType) -> Result<HolePunchedUdpSocket, anyhow::Error> {
    let mut futures = FuturesUnordered::new();
    for mut hole_puncher in hole_punchers {
        futures.push(async move {
            let res = hole_puncher.try_method(NatTraversalMethod::Method3).await;
            (res, hole_puncher)
        });
    }

    let mut map: HashMap<HolePunchID, HolePunchedUdpSocket> = HashMap::new();
    let mut adjacent_completion_id: Option<BTreeSet<HolePunchID>> = None;

    let mut local_successes = BTreeSet::new();

    // if both sides hole-punch identified by each other's local_bind_addr finish first, then this will finish under "if hole_puncher.get_bind_addr() == adjacent_candidate.bind_addr"
    // However, what happens if multiple finish out of order on one side? Assuming both sides for each other's unique hole-punch id finish, then this will eventually finish near "Returning the socket which the adjacent node previously signalled as a success"
    // Finally, what happens if one side registers a success, but for whatever reason, this other side claims to have failed for the same one? Since we won't know for this to be true until after one of the sides exhausts all possibilities,
    while let Some((res, hole_puncher)) = futures.next().await {
        match res {
            Ok(socket) => {
                // the candidate that just finished locally may be what we're waiting for
                if let Some(ref adjacent_candidates) = adjacent_completion_id {
                    for adjacent_candidate in adjacent_candidates {
                        if hole_puncher.get_unique_id() == *adjacent_candidate {
                            log::info!("Returning the socket which the adjacent node previously signalled as a success");
                            return handle_return_sequence(adjacent_candidate.clone(), socket, conn, node_type, &mut map).await;
                        }
                    }
                }

                local_successes.insert(socket.addr.unique_id);
                //local_successes.insert(hole_puncher.get_unique_id());

                // Send the candidate, then wait for the opposite side to respond
                let adjacent_candidate: DualStackCandidate = send_then_receive(DualStackCandidate::SingleHolePunchSuccess(local_successes.clone()), conn).await?;

                match adjacent_candidate {
                    DualStackCandidate::SingleHolePunchSuccess(unique_ids) => {
                        log::info!("Adjacent node signalled completion of hole-punch process w/ {:?}", unique_ids);
                        for unique_id in &unique_ids {
                            // here, we compare local unique id (1) to local unique id (2). (2) is local since above, we input the unique id of the remote addr
                            if hole_puncher.get_unique_id() == *unique_id {
                                log::info!("The completed hole-punch subroutine locally was what the adjacent node expected");
                                return handle_return_sequence(unique_id.clone(), socket, conn, node_type, &mut map).await;
                            } else {
                                // check the history
                                if let Some(prev) = map.remove(unique_id) {
                                    log::info!("Found socket {:?} in the history", unique_id);
                                    return handle_return_sequence(unique_id.clone(), prev, conn, node_type, &mut map).await;
                                }
                            }
                        }

                        log::info!("The locally-completed hole-punched socket is not what the adjacent node signalled. Nor is it done locally. Will discard and keep looping");
                        // this means the local candidate has yet to confirm what the adjacent node has selected. Keep looping, and discard this hole-punch success
                        adjacent_completion_id = Some(unique_ids); // we will wait for the local endpoint to confirm
                        map.insert(hole_puncher.get_unique_id(), socket);
                    }

                    candidate => {
                        return match_resolve(candidate, conn, &mut map).await;
                    }
                }
            }

            Err(err) => {
                log::warn!("Hole-punch for local bind addr {:?} failed: {:?}", hole_puncher.get_unique_id(), err);
            }
        }
    }

    // if we get here, it means one of two things. Either no methods worked locally, or, a method worked
    // locally but because the adjacent node sent a candidate not equal to the candidate obtained locally,
    // it was skipped.

    log::info!("Unable to resolve addrs in main loop. Will have to negotiate ...");
    let working_set = map.keys().cloned().collect::<BTreeSet<HolePunchID>>();
    let candidate: DualStackCandidate = send_then_receive(DualStackCandidate::ResolveUseAnyOf(working_set), conn).await?;
    match_resolve(candidate, conn, &mut map).await
}

/// This gets called when the drive function finds a candidate to return locally. We can't just return results locally since
#[allow(unused_variables)]
async fn handle_return_sequence<V: ReliableOrderedConnectionToTarget>(matched_bind_addr: HolePunchID, candidate: HolePunchedUdpSocket, conn: &V, node_type: RelativeNodeType, map: &mut HashMap<HolePunchID, HolePunchedUdpSocket>) -> Result<HolePunchedUdpSocket, anyhow::Error> {
    Ok(candidate)
}

async fn match_resolve<V: ReliableOrderedConnectionToTarget>(candidate: DualStackCandidate, conn: &V, map: &mut HashMap<HolePunchID, HolePunchedUdpSocket>) -> Result<HolePunchedUdpSocket, anyhow::Error> {
    match candidate {
        DualStackCandidate::ResolveUseAnyOf(working_set) => {
            // we get here if the other side drops out of this loop. There may or may not be any candidates present
            return if working_set.is_empty() {
                // send then exit
                send(DualStackCandidate::Resolved(None), conn).await?;
                Err(anyhow::Error::msg("Unable to resolve; adjacent node had zero successes"))
            } else {
                // we choose the first result that matches
                for working in working_set {
                    if let Some(socket) = map.remove(&working) {
                        send(DualStackCandidate::Resolved(Some(socket.addr.unique_id)), conn).await?;
                        return Ok(socket);
                    }
                }

                // no matches. return err
                send(DualStackCandidate::Resolved(None), conn).await?;
                Err(anyhow::Error::msg("Unable to resolve; adjacent node had zero successes compatible with this node"))
            }
        }

        DualStackCandidate::Resolved(opt) => {
            return if let Some(resolved) = opt {
                map.remove(&resolved).ok_or_else(|| anyhow::Error::msg("Resolved addr does not correspond to any entry locally"))
            } else {
                Err(anyhow::Error::msg("The adjacent node resolved zero candidates compatible with the local node"))
            }
        }

        _ => {
            Err(anyhow::Error::msg("Expected a negotiation packet, but got a success instead ..."))
        }
    }
}

async fn send<R: Serialize, V: ReliableOrderedConnectionToTarget>(ref input: R, conn: &V) -> Result<(), anyhow::Error> {
    Ok(conn.send_to_peer(&bincode2::serialize(input).unwrap()).await?)
}

async fn send_then_receive<T: DeserializeOwned, R: Serialize, V: ReliableOrderedConnectionToTarget>(ref input: R, conn: &V) -> Result<T, anyhow::Error> {
    send(input, conn).await?;
    Ok(bincode2::deserialize(&conn.recv().await?)?)
}

fn increment_ports(bind_addr_0: SocketAddr, peer_external_addr_0: SocketAddr, peer_internal_addr_0: SocketAddr, bind_addr_1: SocketAddr, peer_external_addr_1: SocketAddr, peer_internal_addr_1: SocketAddr, delta: u16) -> (SocketAddr, SocketAddr, SocketAddr, SocketAddr, SocketAddr, SocketAddr) {
    if delta != 0 {
        (increment_port_inner(bind_addr_0, delta), increment_port_inner(peer_external_addr_0, delta), increment_port_inner(peer_internal_addr_0, delta), increment_port_inner(bind_addr_1, delta), increment_port_inner(peer_external_addr_1, delta), increment_port_inner(peer_internal_addr_1, delta))
    } else {
        (bind_addr_0, peer_external_addr_0, peer_internal_addr_0, bind_addr_1, peer_external_addr_1, peer_internal_addr_1)
    }
}

// wraps around at 1024 as recommended by research articles, since [0, 1024) are reserved ports for operating systems usually
fn increment_port_inner(addr: SocketAddr, delta: u16) -> SocketAddr {
    let init_port = addr.port();
    let new_port = init_port.wrapping_add(delta);
    if new_port < 1024 {
        SocketAddr::new(addr.ip(), 1024 + new_port)
    } else {
        SocketAddr::new(addr.ip(), new_port)
    }
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