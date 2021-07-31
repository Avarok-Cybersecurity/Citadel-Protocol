use std::net::{SocketAddr, IpAddr};
use crate::udp_traversal::linear::{SingleUDPHolePuncher, RelativeNodeType};
use crate::udp_traversal::linear::encrypted_config_container::EncryptedConfigContainer;
use crate::reliable_conn::ReliableOrderedConnectionToTarget;
use crate::nat_identification::NatType;
use std::str::FromStr;
use async_ip::IpAddressInfo;
use crate::udp_traversal::hole_punched_udp_socket_addr::{HolePunchedUdpSocket, HolePunchedSocketAddr};
use std::pin::Pin;
use futures::{Future, StreamExt};
use std::task::{Context, Poll};
use futures::stream::FuturesUnordered;
use crate::udp_traversal::{NatTraversalMethod, HolePunchID};
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use tokio::sync::mpsc::{UnboundedSender, UnboundedReceiver};

/// Punches a hole using IPv4/6 addrs. IPv6 is more traversal-friendly since IP-translation between external and internal is not needed (unless the NAT admins are evil)
///
/// allows the inclusion of a "breadth" variable to allow opening multiple ports for traversing across multiple ports
pub(crate) struct DualStackUdpHolePuncher<'a> {
    // the key is the local bind addr
    future: Pin<Box<dyn Future<Output=Result<HolePunchedUdpSocket, anyhow::Error>> + 'a>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(variant_size_differences)]
enum DualStackCandidate {
    SingleHolePunchSuccess(HolePunchID),
    // can be sent by either node
    ResolveLockedIn(HolePunchID),
    // Can only be sent by the initiator/preferred side
    // second is id used for recovery mode only
    Resolved(HolePunchID, Option<HolePunchID>),
    //
    Ping(Vec<HolePunchID>, Vec<HolePunchID>)
}

impl<'a> DualStackUdpHolePuncher<'a> {
    #[allow(unused_results)]
    /// `peer_internal_port`: Required for determining the internal socket addr
    pub fn new<T: ReliableOrderedConnectionToTarget + 'a>(relative_node_type: RelativeNodeType, encrypted_config_container: EncryptedConfigContainer, conn: &'a T, local_nat: &NatType, peer_nat: &NatType, peer_internal_port: u16, breadth: u16) -> Result<Self, anyhow::Error> {
        let (syn_observer_tx, syn_observer_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut hole_punchers = Vec::new();
        let ref mut init_unique_id = HolePunchID(0);
        Self::generate_dual_stack_hole_punchers_with_delta(&mut hole_punchers, relative_node_type, encrypted_config_container.clone(), conn, local_nat, peer_nat, peer_internal_port, 0, init_unique_id, syn_observer_tx.clone())?;

        if breadth > 1 {
            for delta in 1..breadth {
                Self::generate_dual_stack_hole_punchers_with_delta(&mut hole_punchers, relative_node_type, encrypted_config_container.clone(), conn, local_nat, peer_nat, peer_internal_port, delta, init_unique_id, syn_observer_tx.clone())?;
            }
        }

        Ok(Self { future: Box::pin(drive(hole_punchers, conn, relative_node_type, syn_observer_rx)) })
    }

    fn generate_dual_stack_hole_punchers_with_delta<T: ReliableOrderedConnectionToTarget + 'a>(hole_punchers: &mut Vec<SingleUDPHolePuncher>, relative_node_type: RelativeNodeType, encrypted_config_container: EncryptedConfigContainer, conn: &'a T, local_nat: &NatType, peer_nat: &NatType, peer_internal_port: u16, delta: u16, unique_id: &mut HolePunchID, syn_observer: UnboundedSender<(HolePunchID, HolePunchID, HolePunchedSocketAddr)>) -> Result<(), anyhow::Error> {
        let peer_ip_info = peer_nat.ip_addr_info().ok_or_else(|| anyhow::Error::msg("Peer IP info not loaded"))?;
        let local_ip_info = local_nat.ip_addr_info().ok_or_else(|| anyhow::Error::msg("Local IP info not loaded"))?;

        let bind_addr_0 = conn.local_addr()?;
        let peer_external_addr_0 = conn.peer_addr()?;
        let peer_internal_addr_0 = SocketAddr::new(peer_ip_info.internal_ipv4, peer_internal_port);

        let (bind_addr_1, peer_external_addr_1, peer_internal_addr_1) = invert(bind_addr_0, peer_external_addr_0, peer_internal_addr_0, peer_ip_info)?;

        let (bind_addr_0, peer_external_addr_0, peer_internal_addr_0, bind_addr_1, peer_external_addr_1, peer_internal_addr_1) = increment_ports(bind_addr_0, peer_external_addr_0, peer_internal_addr_0, bind_addr_1, peer_external_addr_1, peer_internal_addr_1, delta);

        // As long as there is translation, we will can attempt dual ipv4/6 hole-punching. This requires that the peer has an IPv6 address
        // also, if THIS node has an IPv6 address, then the adjacent node will attempt to connect to it, so in that case, we will need to bind regardless to ipv6 addrs IF the zeroth hole-puncher is not already ipv6
        // in other words: if this side has ipv6, or if the other side has ipv6, bind to ipv6 ports
        if (peer_external_addr_1 != peer_external_addr_0 && peer_internal_addr_1 != peer_external_addr_0 && bind_addr_0 != bind_addr_1) || (bind_addr_0.is_ipv4() && local_ip_info.external_ipv6.is_some()) {
            let hole_puncher1 = SingleUDPHolePuncher::new(relative_node_type, encrypted_config_container.clone(), bind_addr_1, peer_external_addr_1, peer_internal_addr_1, unique_id.next(), syn_observer.clone())?;
            hole_punchers.push(hole_puncher1);
        }

        let hole_puncher0 = SingleUDPHolePuncher::new(relative_node_type, encrypted_config_container, bind_addr_0, peer_external_addr_0, peer_internal_addr_0, unique_id.next(), syn_observer)?;

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

async fn drive<'a, T: ReliableOrderedConnectionToTarget + 'a>(hole_punchers: Vec<SingleUDPHolePuncher>, conn: &'a T, node_type: RelativeNodeType, mut syn_observer_rx: UnboundedReceiver<(HolePunchID, HolePunchID, HolePunchedSocketAddr)>) -> Result<HolePunchedUdpSocket, anyhow::Error> {
    let (final_candidate_tx, final_candidate_rx) = tokio::sync::oneshot::channel::<HolePunchedUdpSocket>();
    let (reader_done_tx, mut reader_done_rx) = tokio::sync::broadcast::channel::<()>(2);
    let mut reader_done_rx_2 = reader_done_tx.subscribe();

    let (ref kill_signal_tx, _kill_signal_rx) = tokio::sync::broadcast::channel(hole_punchers.len());
    let (ref post_rebuild_tx, mut post_rebuild_rx) = tokio::sync::mpsc::unbounded_channel();
    //let ref post_rebuild_tx = post_rebuild_tx;

    let assert_rebuild_ready = |local_id: HolePunchID, peer_id: HolePunchID, addr: HolePunchedSocketAddr| async move {
        let _receivers = kill_signal_tx.send((local_id, peer_id, addr))?;
        if let Some(Some(val)) = post_rebuild_rx.recv().await {
            Ok(val)
        } else {
            Err(anyhow::Error::msg("Failed to rebuild socket"))
        }
    };

    let ref mut final_candidate_tx = Some(final_candidate_tx);

    let mut futures = FuturesUnordered::new();
    for (kill_switch_rx, mut hole_puncher) in hole_punchers.into_iter().map(|r| (kill_signal_tx.subscribe(), r)) {
        futures.push(async move {
            let res = hole_puncher.try_method(NatTraversalMethod::Method3, kill_switch_rx, post_rebuild_tx.clone()).await;
            (res, hole_puncher)
        });
    }

    // key = local
    let ref local_completions: RwLock<HashMap<HolePunchID, (HolePunchedUdpSocket, SingleUDPHolePuncher)>> = RwLock::new(HashMap::new());
    let ref local_failures: RwLock<HashMap<HolePunchID, SingleUDPHolePuncher>> = RwLock::new(HashMap::new());
    let ref syns_observed_map: RwLock<HashSet<(HolePunchID, HolePunchID, HolePunchedSocketAddr)>> = RwLock::new(HashSet::new());

    let syns_observed = async move {
        while let Some((local_id, peer_id, addr)) = syn_observer_rx.recv().await {
            let _ = syns_observed_map.write().await.insert((local_id, peer_id, addr));
        }

        Ok(reader_done_rx_2.recv().await?) as Result<(), anyhow::Error>
    };

    // the goal of the sender is just to send results as local finishes, nothing else
    let sender = async move {
        while let Some((res, hole_puncher)) = futures.next().await {
            match res {
                Ok(socket) => {
                    let peer_unique_id = socket.addr.unique_id;
                    // we insert the local unique id into the map
                    log::info!("Inserting {:?} into the local hashmap", hole_puncher.get_unique_id());
                    local_completions.write().await.insert(hole_puncher.get_unique_id(), (socket, hole_puncher));
                    log::info!("DONE inserting");
                    // we send the per unique id to the adjacent node, they way they can use their map to access the value since the map corresponds to local only values
                    send(DualStackCandidate::SingleHolePunchSuccess(peer_unique_id), conn).await?;
                }

                Err(err) => {
                    log::warn!("Hole-punch for local bind addr {:?} failed: {:?}", hole_puncher.get_unique_id(), err);
                    local_failures.write().await.insert(hole_puncher.get_unique_id(), hole_puncher);
                }
            }
        }

        // if we get here before the reader finishes, we need to wait for the reader to finish
        Ok(reader_done_rx.recv().await?) as Result<(), anyhow::Error>
        //Ok(()) as Result<(), anyhow::Error>
    };

    let has_precedence = node_type == RelativeNodeType::Receiver;
    let ref mut locked_in_locally = None;
    // stores the remote id that way it may be accessed during the Resolve stage if local already submitted
    let ref mut this_node_submitted: Option<HolePunchID> = None;

    // the goal of the reader is to read inbound candidates, check the local hashmap for correspondence, then engage in negotiation if required
    let reader = async move {
        let _reader_done_tx = reader_done_tx; // move into the closure, preventing the sender future from ending and causing this future to end pre-maturely
        while let Ok(candidate) = receive::<DualStackCandidate, _>(conn).await {
            log::info!("MAIN RECV {:?}", &candidate);
            match candidate {
                DualStackCandidate::SingleHolePunchSuccess(ref local_unique_id) => {
                    if this_node_submitted.is_none() {
                        if locked_in_locally.clone() == Some(local_unique_id.clone()) {
                            log::info!("Previously locked-in locally identified. Will unconditionally accept if local has preference");
                            if has_precedence {
                                // since both nodes are implied to have the hole-punched sockets for the locked-in ID,
                                log::info!("Local has preference. Completing subroutine locally");
                                // we can unwrap here since locked_in_locally existing implies the existence of the entry in the local hashmap
                                let (hole_punched_socket, _hole_puncher) = local_completions.write().await.remove(local_unique_id).unwrap();
                                // send the adjacent id to remote per usual
                                let peer_id = hole_punched_socket.addr.unique_id;
                                send(DualStackCandidate::Resolved(peer_id, None), conn).await?;
                                final_candidate_tx.take().unwrap().send(hole_punched_socket).map_err(|_| anyhow::Error::msg("oneshot send error"))?;
                                *this_node_submitted = Some(peer_id);
                            } else {
                                log::info!("Local does NOT have preference. Will await for the adjacent endpoint to send confirmation")
                            }
                        } else {
                            let mut write = local_completions.write().await;
                            if let Some((local_candidate, local_hole_puncher)) = write.get(local_unique_id) {
                                log::info!("Matched local id {:?} to remote id {:?} | has precedence? {}", local_hole_puncher.get_unique_id(), local_candidate.addr.unique_id, has_precedence);
                                let peer_id = local_candidate.addr.unique_id;
                                if has_precedence {
                                    // both sides have this, and this side has precedence, so finish early
                                    let (hole_punched_socket, _hole_puncher) = write.remove(local_unique_id).unwrap();
                                    // send the adjacent id to remote per usual

                                    std::mem::drop(write);
                                    send(DualStackCandidate::Resolved(peer_id, None), conn).await?;
                                    final_candidate_tx.take().unwrap().send(hole_punched_socket).map_err(|_| anyhow::Error::msg("oneshot send error"))?;
                                    *this_node_submitted = Some(peer_id);
                                    return Ok(())
                                } else {
                                    // both sides have this, though, this node does not have the power to confirm first. It needs to send a ResolveLockedIn to the other side, where it will return with a Resolved if the adjacent side finished
                                    *locked_in_locally = Some(local_unique_id.clone());
                                    // sent the remote unique ID
                                    std::mem::drop(write);
                                    send(DualStackCandidate::ResolveLockedIn(peer_id), conn).await?;
                                    // we send this, then keep looping until getting an appropriate response
                                }
                            } else {
                                log::info!("Pinging since local has no matches. Available: {:?}", write.keys());
                                // value does not exist in ANY of the local values. Keep waiting
                                // note: experimentally, it has been proven possible that what succeeds on one end may fail on another. This means when remote succeeds for id X, but local fails for X, we enter an infinite loop of pings until timeout occurs

                                //let local_received_ids = construct_received_ids(&*local_failures.read().await, &*write);
                                let local_received_syns = construct_received_ids(&*syns_observed_map.read().await);
                                let local_completed = write.keys().cloned().collect();
                                std::mem::drop(write);
                                send(DualStackCandidate::Ping(local_completed, local_received_syns.into_iter().map(|r| r.0).collect()), conn).await?;
                            }
                        }
                    } else {
                        log::warn!("This node already submitted");
                    }
                }

                // a ping can be sent from either receiver or initiator. If the local receiver is the initiator, and it discovers a potential candidate, only it is allowed to accept a version then send a resolved instead of a Pong
                // if the local receiver is the receiver, then it must return a ping to the initiator of the local state so that it may resolve
                DualStackCandidate::Ping(remote_successes, ref remote_received_ids) => {
                    if has_precedence {
                        // we must resolve
                        let mut write = local_completions.write().await;
                        for remote_success in &remote_successes {
                            if let Some((key, _)) = write.iter().find(|(_key,(socket, _puncher))| socket.addr.unique_id == *remote_success) {
                                let ref key = key.clone();
                                log::info!("RESOLVED with {:?}", key);
                                let (hole_punched_socket, _) = write.remove(key).unwrap();
                                // this side is done
                                std::mem::drop(write);
                                send(DualStackCandidate::Resolved(*remote_success, None), conn).await?;
                                final_candidate_tx.take().unwrap().send(hole_punched_socket).map_err(|_| anyhow::Error::msg("oneshot send error"))?;
                                *this_node_submitted = Some(*remote_success);
                                return Ok(())
                            }
                        }

                        // no matching resolutions. However, it is possible that there exists at least one success. One success existing implies a necessarily existent bidirectional communication, even if one side for whatever reason failed
                        if remote_successes.len() > 0 || write.len() > 0 {
                            log::info!("[Recovery] Will begin the recovery process since at least one bidirectional completion occurred ...");
                            // at least one success occurred. Start by examining local (which has precedence) for a success
                            if write.len() > 0 {
                                log::info!("[Recovery] Local has preference and has at least one success. Will see if remote can recover ...");
                                for local_id in remote_received_ids {
                                    if let Some((hole_punched_socket, _)) = write.remove(local_id) {
                                        log::info!("[Recovery] Found MATCH with local={:?}", local_id);
                                        // send a Resolved
                                        let remote_id = hole_punched_socket.addr.unique_id;
                                        // remote will need to reconstruct
                                        send(DualStackCandidate::Resolved(remote_id, Some(*local_id)), conn).await?;
                                        final_candidate_tx.take().unwrap().send(hole_punched_socket).map_err(|_| anyhow::Error::msg("oneshot send error"))?;
                                        *this_node_submitted = Some(remote_id);
                                        return Ok(())
                                    }
                                }
                            }

                            if remote_successes.len() > 0 {
                                log::info!("[Recovery] Local has preference, and, remote has at least one success. If local has a received ID corresponding to a remote id, will conclude");
                                //let mut local_failures = local_failures.write().await;
                                //let local_received_ids = construct_received_ids(&*local_failures, &*write);
                                let local_received_syns = construct_received_ids(&*syns_observed_map.read().await);
                                for (remote_id, local_id, addr) in local_received_syns {
                                    if remote_successes.contains(&remote_id) {
                                        log::info!("[Recovery] Found MATCH with remote={:?}", remote_id);
                                        //let hole_punched_socket = local_failures.remove(local_id).unwrap().recovery_mode_generate_socket(*remote_id).unwrap();
                                        let hole_punched_socket = assert_rebuild_ready(local_id, remote_id, addr).await?;
                                        // since this is recovery mode, yet, remote was the one with the success, we pass None
                                        //std::mem::drop(local_failures);
                                        send(DualStackCandidate::Resolved(remote_id, None), conn).await?;
                                        final_candidate_tx.take().unwrap().send(hole_punched_socket).map_err(|_| anyhow::Error::msg("oneshot send error"))?;
                                        *this_node_submitted = Some(remote_id);
                                        return Ok(())
                                    }
                                }
                            }
                        }

                        log::info!("No resolution obtained. Will keep looping");
                        // no resolution. Send a ping. Note: the below is pointless since the adjacent node won't resolve it
                        //let local_received_ids = construct_received_ids(&*local_failures.read().await, &*write);
                        let local_received_syns = construct_received_ids(&*syns_observed_map.read().await);
                        send(DualStackCandidate::Ping(write.keys().cloned().collect(), local_received_syns.into_iter().map(|r| r.0).collect()), conn).await?;
                    } else {
                        // this side will only resolve once the ping resolves remotely on the initiator side. We send the information needed for recovery mode (if needed) that way the preferred side may resolve
                        let read = local_completions.read().await;
                        //let received_ids = construct_received_ids(&*local_failures.read().await, &*read);
                        let local_received_syns = construct_received_ids(&*syns_observed_map.read().await);
                        send(DualStackCandidate::Ping(read.keys().cloned().collect(), local_received_syns.into_iter().map(|r| r.0).collect()), conn).await?;
                    }
                }

                DualStackCandidate::Resolved(ref local_unique_id, recovery_mode) => {
                    // we unconditionally send local's value in the hashmap, which is implied to exist locally so we can unwrap
                    debug_assert!(!has_precedence);
                    let hole_punched_socket = if let Some(recovery_id) = recovery_mode {
                        // we check both successes and failures. It MUST be one of the two
                        if let Some((socket, _b)) = local_completions.write().await.remove(local_unique_id) {
                            socket
                        } else {
                            // if it's not in the successes, it must be in the failures, thus we can unwrap all the way
                            log::info!("Engaging recovery mode to rebuild socket that the adjacent node claimed functioned ...");
                            local_failures.write().await.remove(local_unique_id).unwrap().recovery_mode_generate_socket_by_remote_id(recovery_id).unwrap()
                        }
                    } else {
                        let (hole_punched_socket, _hole_puncher) = local_completions.write().await.remove(local_unique_id).unwrap();
                        hole_punched_socket
                    };

                    final_candidate_tx.take().unwrap().send(hole_punched_socket).map_err(|_| anyhow::Error::msg("oneshot send error"))?;
                    return Ok(())
                }

                DualStackCandidate::ResolveLockedIn(ref local_unique_id) => {
                    // How did we get here? This side sends a SingleHolePunchSuccess, then, the adjacent side confirms that it also has finished connecting with local_unique_id. It then sends this packet to this node
                    // Both sides have local_unique_id saved locally. The only side that RECEIVES the ResolveLockedIn is the precedence side; it must send an ack back
                    debug_assert!(has_precedence);

                    // it is possible that this side already resolved, in which case unwrapping below would yield a panic. Instead, just send an Resolved
                    return if let Some(peer_id) = this_node_submitted.clone() {
                        send(DualStackCandidate::Resolved(peer_id, None), conn).await?;
                        Ok(())
                    } else {
                        // we finish on local, then send a resolved
                        let (hole_punched_socket, _hole_puncher) = local_completions.write().await.remove(local_unique_id).unwrap();
                        // send the adjacent id to remote per usual
                        send(DualStackCandidate::Resolved(hole_punched_socket.addr.unique_id, None), conn).await?;
                        final_candidate_tx.take().unwrap().send(hole_punched_socket).map_err(|_| anyhow::Error::msg("oneshot send error"))?;
                        //this_node_submitted = true;
                        Ok(())
                    }
                }
            }
        }

        Err(anyhow::Error::msg("The reliable ordered stream stopped producing values"))
    };

    // this will end once the reader ends. The sender won't end until at least after the reader ends (unless there is a transmission error)
    tokio::select! {
        res0 = sender => res0?,
        res1 = reader => res1?,
        res2 = syns_observed => res2?,
    };

    Ok(final_candidate_rx.await?)
}

/// returns mapping of (remote_id, local_id)
fn construct_received_ids(received_syns: &HashSet<(HolePunchID, HolePunchID, HolePunchedSocketAddr)>) -> Vec<(HolePunchID, HolePunchID, HolePunchedSocketAddr)> {
    let mut ret: Vec<(HolePunchID, HolePunchID, HolePunchedSocketAddr)> = Vec::new();

    for (local_id, remote_id, addr) in received_syns.iter() {
        ret.push((*local_id, *remote_id, *addr));
    }

    ret
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