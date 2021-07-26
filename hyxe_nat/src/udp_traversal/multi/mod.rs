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
use std::collections::HashMap;
use parking_lot::Mutex;
use std::sync::Arc;

/// Punches a hole using IPv4/6 addrs. IPv6 is more traversal-friendly since IP-translation between external and internal is not needed (unless the NAT admins are evil)
///
/// allows the inclusion of a "breadth" variable to allow opening multiple ports for traversing across multiple ports
pub(crate) struct DualStackUdpHolePuncher<'a> {
    // the key is the local bind addr
    future: Pin<Box<dyn Future<Output=Result<HolePunchedUdpSocket, anyhow::Error>> + 'a>>,
}

#[derive(Serialize, Deserialize, Debug)]
enum DualStackCandidate {
    SingleHolePunchSuccess(HolePunchID),
    // can be sent by either node
    ResolveLockedIn(HolePunchID),
    // Can only be sent by the initiator/preferred side
    Resolved(HolePunchID),
    //
    Ping(HolePunchID),
    Pong(HolePunchID)
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
    let (final_candidate_tx, final_candidate_rx) = tokio::sync::oneshot::channel::<HolePunchedUdpSocket>();
    let (reader_done_tx, reader_done_rx) = tokio::sync::oneshot::channel::<()>();

    let ref mut final_candidate_tx = Some(final_candidate_tx);

    for mut hole_puncher in hole_punchers {
        futures.push(async move {
            let res = hole_puncher.try_method(NatTraversalMethod::Method3).await;
            (res, hole_puncher)
        });
    }

    // key = local
    let ref local_completions: Arc<Mutex<HashMap<HolePunchID, (HolePunchedUdpSocket, SingleUDPHolePuncher)>>> = Arc::new(Mutex::new(HashMap::new()));
    let ref local_completions_sender = local_completions.clone();
    //let ref mut adjacent_completion_ids: BTreeSet<HolePunchID> = BTreeSet::new();

    // the goal of the sender is just to send results as local finishes, nothing else
    let sender = async move {
        while let Some((res, hole_puncher)) = futures.next().await {
            match res {
                Ok(socket) => {
                    let peer_unique_id = socket.addr.unique_id;
                    // we insert the local unique id into the map
                    local_completions.lock().insert(hole_puncher.get_unique_id(), (socket, hole_puncher));
                    // we send the per unique id to the adjacent node, they way they can use their map to access the value since the map corresponds to local only values
                    send(DualStackCandidate::SingleHolePunchSuccess(peer_unique_id), conn).await?;
                }

                Err(err) => {
                    log::warn!("Hole-punch for local bind addr {:?} failed: {:?}", hole_puncher.get_unique_id(), err);
                }
            }
        }

        // if we get here before the reader finishes, we need to wait for the reader to finish
        Ok(reader_done_rx.await?) as Result<(), anyhow::Error>
    };

    let has_precedence = node_type == RelativeNodeType::Initiator;
    let ref mut locked_in_locally = None;

    let mut this_node_submitted = false;

    // the goal of the reader is to read inbound candidates, check the local hashmap for correspondence, then engage in negotiation if required
    let reader = async move {
        let _reader_done_tx = reader_done_tx; // move into the closure, preventing the sender future from ending and causing this future to end pre-maturely
        while let Ok(candidate) = receive::<DualStackCandidate, _>(conn).await {
            log::info!("RECV {:?}", &candidate);
            match candidate {
                DualStackCandidate::SingleHolePunchSuccess(ref local_unique_id) | DualStackCandidate::Pong(ref local_unique_id) => {
                    if !this_node_submitted {
                        if locked_in_locally.clone() == Some(local_unique_id.clone()) {
                            log::info!("Previously locked-in locally identified. Will unconditionally accept if local has preference");
                            if has_precedence {
                                // since both nodes are implied to have the hole-punched sockets for the locked-in ID,
                                log::info!("Local has preference. Completing subroutine locally");
                                // we can unwrap here since locked_in_locally existing implies the existence of the entry in the local hashmap
                                let (hole_punched_socket, _hole_puncher) = local_completions_sender.lock().remove(local_unique_id).unwrap();
                                // send the adjacent id to remote per usual
                                send(DualStackCandidate::Resolved(hole_punched_socket.addr.unique_id), conn).await?;
                                final_candidate_tx.take().unwrap().send(hole_punched_socket).map_err(|_| anyhow::Error::msg("oneshot send error"))?;
                                this_node_submitted = true;
                            } else {
                                log::info!("Local does NOT have preference. Will await for the adjacent endpoint to send confirmation")
                            }
                        }

                        if let Some((local_candidate, _local_hole_puncher)) = local_completions.lock().get(local_unique_id) {
                            if has_precedence {
                                // both sides have this, and this side has precedence, so finish early
                                let (hole_punched_socket, _hole_puncher) = local_completions.lock().remove(local_unique_id).unwrap();
                                // send the adjacent id to remote per usual
                                send(DualStackCandidate::Resolved(hole_punched_socket.addr.unique_id), conn).await?;
                                final_candidate_tx.take().unwrap().send(hole_punched_socket).map_err(|_| anyhow::Error::msg("oneshot send error"))?;
                                this_node_submitted = true;
                            } else {
                                // both sides have this, though, this node does not have the power to confirm first. It needs to send a ResolveLockedIn to the other side, where it will return with a Resolved if the adjacent side finished
                                *locked_in_locally = Some(local_unique_id.clone());
                                // sent the remote unique ID
                                send(DualStackCandidate::ResolveLockedIn(local_candidate.addr.unique_id), conn).await?;
                                // we send this, then keep looping until getting an appropriate response
                            }
                        } else {
                            // value does not exist in ANY of the local values. Keep waiting
                            *locked_in_locally = Some(local_unique_id.clone());
                            send(DualStackCandidate::Ping(local_unique_id.clone()), conn).await?;
                        }
                    }
                }

                DualStackCandidate::Ping(id) => {
                    send(DualStackCandidate::Pong(id), conn).await?;
                }

                DualStackCandidate::Resolved(ref local_unique_id) => {
                    // we unconditionally send local's value in the hashmap, which is implied to exist locally so we can unwrap
                    debug_assert!(!has_precedence);
                    let (hole_punched_socket, _hole_puncher) = local_completions.lock().remove(local_unique_id).unwrap();
                    final_candidate_tx.take().unwrap().send(hole_punched_socket).map_err(|_| anyhow::Error::msg("oneshot send error"))?;
                    return Ok(())
                }

                DualStackCandidate::ResolveLockedIn(ref local_unique_id) => {
                    // How did we get here? This side sends a SingleHolePunchSuccess, then, the adjacent side confirms that it also has finished connecting with local_unique_id. It then sends this packet to this node
                    // Both sides have local_unique_id saved locally. The only side that RECEIVES the ResolveLockedIn is the precedence side; it must send an ack back
                    debug_assert!(has_precedence);

                    // we finish on local, then send a resolved
                    let (hole_punched_socket, _hole_puncher) = local_completions.lock().remove(local_unique_id).unwrap();
                    // send the adjacent id to remote per usual
                    send(DualStackCandidate::Resolved(hole_punched_socket.addr.unique_id), conn).await?;
                    final_candidate_tx.take().unwrap().send(hole_punched_socket).map_err(|_| anyhow::Error::msg("oneshot send error"))?;
                    //this_node_submitted = true;
                    return Ok(())
                }
            }
        }

        Err(anyhow::Error::msg("The reliable ordered stream stopped producing values"))
    };

    // this will end once the reader ends. The sender won't end until at least after the reader ends (unless there is a transmission error)
    tokio::select! {
        res0 = sender => res0?,
        res1 = reader => res1?
    };

    Ok(final_candidate_rx.await?)
}

async fn send<R: Serialize, V: ReliableOrderedConnectionToTarget>(ref input: R, conn: &V) -> Result<(), anyhow::Error> {
    Ok(conn.send_to_peer(&bincode2::serialize(input).unwrap()).await?)
}

async fn receive<T: DeserializeOwned, V: ReliableOrderedConnectionToTarget>(conn: &V) -> Result<T, anyhow::Error> {
    Ok(bincode2::deserialize(&conn.recv().await?)?)
}

#[allow(dead_code)]
async fn send_then_receive<T: DeserializeOwned, R: Serialize, V: ReliableOrderedConnectionToTarget>(ref input: R, conn: &V) -> Result<T, anyhow::Error> {
    send(input, conn).await?;
    receive(conn).await
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