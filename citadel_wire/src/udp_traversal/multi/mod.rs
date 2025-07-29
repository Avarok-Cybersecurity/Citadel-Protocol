//! Dual-Stack UDP Hole Punching Framework
//!
//! This module implements a concurrent UDP hole punching framework that supports
//! both IPv4 and IPv6. It manages multiple hole punching attempts across different
//! ports and protocols, coordinating between them to select the most successful
//! connection path.
//!
//! # Features
//!
//! - Concurrent IPv4/IPv6 traversal
//! - Multi-port hole punching
//! - Winner selection protocol
//! - Failure recovery handling
//! - Multiplexed connections
//! - Asynchronous coordination
//!
//! # Examples
//!
//! ```rust
//! use citadel_wire::udp_traversal::multi::DualStackUdpHolePuncher;
//! use citadel_wire::udp_traversal::hole_punched_socket::HolePunchedUdpSocket;
//! use citadel_wire::udp_traversal::hole_punch_config::HolePunchConfig;
//! use citadel_wire::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
//! use netbeam::sync::RelativeNodeType;
//! use netbeam::sync::network_endpoint::NetworkEndpoint;
//!
//! async fn establish_connection(
//!     node_type: RelativeNodeType,
//!     config: HolePunchConfigContainer,
//!     hole_punch_config: HolePunchConfig,
//!     network: NetworkEndpoint
//! ) -> Result<HolePunchedUdpSocket, anyhow::Error> {
//!     let puncher = DualStackUdpHolePuncher::new(
//!         node_type,
//!         config,
//!         hole_punch_config,
//!         network
//!     )?;
//!     
//!     puncher.await
//! }
//! ```
//!
//! # Important Notes
//!
//! - IPv6 preferred for traversal
//! - Concurrent attempts coordinated
//! - Winner selection is atomic
//! - Failures trigger fallbacks
//! - Network multiplexing required
//!
//! # Related Components
//!
//! - [`crate::udp_traversal::linear::SingleUDPHolePuncher`] - Linear punching
//! - [`crate::hole_punch_config`] - Configuration
//! - [`crate::nat_identification`] - NAT analysis
//! - [`netbeam::multiplex`] - Connection multiplexing
//!

use crate::error::FirewallError;
use crate::udp_traversal::hole_punch_config::HolePunchConfig;
use crate::udp_traversal::hole_punched_socket::HolePunchedUdpSocket;
use crate::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
use crate::udp_traversal::linear::SingleUDPHolePuncher;
use crate::udp_traversal::{HolePunchID, NatTraversalMethod};
use citadel_io::tokio::sync::mpsc::UnboundedReceiver;
use futures::future::select_ok;
use futures::stream::FuturesUnordered;
use futures::{Future, StreamExt};
use netbeam::multiplex::MultiplexedConn;
use netbeam::sync::channel::bi_channel::{ChannelRecvHalf, ChannelSendHalf};
use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::RelativeNodeType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

/// Punches a hole using IPv4/6 addrs. IPv6 is more traversal-friendly since IP-translation between external and internal is not needed (unless the NAT admins are evil)
///
/// allows the inclusion of a "breadth" variable to allow opening multiple ports for traversing across multiple ports
pub struct DualStackUdpHolePuncher {
    // the key is the local bind addr
    future:
        Pin<Box<dyn Future<Output = Result<HolePunchedUdpSocket, anyhow::Error>> + Send + 'static>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[allow(variant_size_differences)]
enum DualStackCandidateSignal {
    Winner(HolePunchID, HolePunchID),
    WinnerCanEnd,
    AllFailed,
}

impl DualStackUdpHolePuncher {
    /// `peer_internal_port`: Required for determining the internal socket addr
    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(level = "trace", target = "citadel", skip_all, err(Debug))
    )]
    pub fn new(
        relative_node_type: RelativeNodeType,
        encrypted_config_container: HolePunchConfigContainer,
        mut hole_punch_config: HolePunchConfig,
        napp: NetworkEndpoint,
    ) -> Result<Self, anyhow::Error> {
        let mut hole_punchers = Vec::new();
        let sockets = hole_punch_config
            .locally_bound_sockets
            .take()
            .ok_or_else(|| anyhow::Error::msg("sockets already taken"))?;
        let addrs_to_ping = hole_punch_config
            .into_iter()
            .collect::<Vec<Vec<SocketAddr>>>();

        // each individual hole puncher fans-out from 1 bound socket to n many peer addrs (determined by addrs_to_ping)
        for (socket, mut addrs_to_ping) in sockets.into_iter().zip(addrs_to_ping) {
            let socket_local_addr = socket.local_addr()?;
            // We can't send from an ipv4 socket to an ipv6, addr, so remove any addrs that are ipv6
            if socket_local_addr.is_ipv4() {
                addrs_to_ping.retain(|addr| addr.is_ipv4());
            }

            // We can't send from an ipv6 socket to and ipv4, addr, so remove any addrs that are ipv4
            if socket_local_addr.is_ipv6() {
                addrs_to_ping.retain(|addr| addr.is_ipv6());
            }

            log::trace!(target: "citadel", "Hole punching with socket: {socket_local_addr} | addrs to ping: {addrs_to_ping:?}");
            let hole_puncher = SingleUDPHolePuncher::new(
                relative_node_type,
                encrypted_config_container.clone(),
                socket,
                addrs_to_ping.clone(),
            )?;
            hole_punchers.push(hole_puncher);
        }

        // TODO: Setup concurrent UPnP AND NAT-PMP async https://docs.rs/natpmp/latest/natpmp/struct.NatpmpAsync.html
        let task = async move {
            citadel_io::tokio::task::spawn(drive(hole_punchers, relative_node_type, napp))
                .await
                .map_err(|err| anyhow::Error::msg(format!("panic in hole puncher: {err:?}")))?
        };

        Ok(Self {
            future: Box::pin(task),
        })
    }
}

impl Future for DualStackUdpHolePuncher {
    type Output = Result<HolePunchedUdpSocket, anyhow::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

#[cfg_attr(
    feature = "localhost-testing",
    tracing::instrument(level = "trace", target = "citadel", skip_all, ret, err(Debug))
)]
async fn drive(
    hole_punchers: Vec<SingleUDPHolePuncher>,
    node_type: RelativeNodeType,
    app: NetworkEndpoint,
) -> Result<HolePunchedUdpSocket, anyhow::Error> {
    // We use a single mutex to resolve timing/priority conflicts automatically
    // Which ever node FIRST can set the value will "win"
    let value = if node_type == RelativeNodeType::Initiator {
        Some(None)
    } else {
        None
    };

    log::trace!(target: "citadel", "Initiating subscription ...");
    // initiate a dedicated channel for sending packets for coordination
    let conn = app.bi_channel::<DualStackCandidateSignal>().await?;
    let (ref conn_tx, conn_rx) = conn.split();
    let conn_rx = &citadel_io::tokio::sync::Mutex::new(conn_rx);

    log::trace!(target: "citadel", "Initiating NetMutex ...");
    // setup a mutex for handling contentions
    let net_mutex = &(app
        .mutex::<Option<(HolePunchID, HolePunchID)>>(value)
        .await?);

    let (final_candidate_tx, final_candidate_rx) =
        citadel_io::tokio::sync::oneshot::channel::<HolePunchedUdpSocket>();

    let (ref kill_signal_tx, _kill_signal_rx) =
        citadel_io::tokio::sync::broadcast::channel(hole_punchers.len());
    let (ref post_rebuild_tx, post_rebuild_rx) = citadel_io::tokio::sync::mpsc::unbounded_channel();

    let final_candidate_tx = &mut citadel_io::Mutex::new(Some(final_candidate_tx));

    let submit_final_candidate = &(|candidate: HolePunchedUdpSocket| -> Result<(), anyhow::Error> {
        let tx = final_candidate_tx
            .lock()
            .take()
            .ok_or_else(|| anyhow::Error::msg("submit_final_candidate has already been called"))?;
        tx.send(candidate)
            .map_err(|_| anyhow::Error::msg("Unable to submit final candidate"))
    });

    struct RebuildReadyContainer {
        local_failures: HashMap<HolePunchID, SingleUDPHolePuncher>,
        post_rebuild_rx: Option<UnboundedReceiver<Option<HolePunchedUdpSocket>>>,
    }

    let rebuilder = &citadel_io::tokio::sync::Mutex::new(RebuildReadyContainer {
        local_failures: HashMap::new(),
        post_rebuild_rx: Some(post_rebuild_rx),
    });

    let mut futures = FuturesUnordered::new();
    for (kill_switch_rx, mut hole_puncher) in hole_punchers
        .into_iter()
        .map(|r| (kill_signal_tx.subscribe(), r))
    {
        // TODO: Consider spawning to ensure if the reader/future-processor fail,
        // the background still can send its results to the background rebuilder
        let post_rebuild_tx = post_rebuild_tx.clone();
        let task = async move {
            let res = hole_puncher
                .try_method(NatTraversalMethod::Method3, kill_switch_rx, post_rebuild_tx)
                .await;
            (res, hole_puncher)
        };

        let task = citadel_io::tokio::task::spawn(task);

        futures.push(task);
    }

    let current_enqueued_set: &citadel_io::tokio::sync::Mutex<Vec<HolePunchedUdpSocket>> =
        &citadel_io::tokio::sync::Mutex::new(vec![]);
    let finished_count = &citadel_io::Mutex::new(0);
    let hole_puncher_count = futures.len();

    let commanded_winner = &citadel_io::tokio::sync::Mutex::new(None);

    let (done_tx, done_rx) = citadel_io::tokio::sync::oneshot::channel::<()>();
    let done_tx = citadel_io::Mutex::new(Some(done_tx));

    let signal_done = || -> Result<(), anyhow::Error> {
        let tx = done_tx
            .lock()
            .take()
            .ok_or_else(|| anyhow::Error::msg("signal_done has already been called"))?;
        tx.send(())
            .map_err(|_| anyhow::Error::msg("signal_done oneshot sender failed to send"))
    };

    let failure_occurred = &AtomicBool::new(false);
    let set_failure_occurred = || async move {
        let no_failure_yet = !failure_occurred.fetch_or(true, Ordering::SeqCst);
        if no_failure_yet {
            log::trace!(target: "citadel", "All hole-punchers have failed locally. Will send AllFailed signal");
            send(DualStackCandidateSignal::AllFailed, conn_tx).await?;
            Ok(())
        } else {
            // In this case, remote already set_failure_occurred, so we know that since they
            // failed, and now that we failed, we can end.
            log::error!(target: "citadel", "Remote has already failed, and locally failed, therefore returning");
            Err(anyhow::Error::msg(
                "All local and remote hold punchers failed",
            ))
        }
    };

    // This is called to scan currently-running tasks to terminate, and, returning the rebuilt
    // hole-punched socket on completion
    let loser_rebuilder_task = async move {
        let mut lock = rebuilder.lock().await;
        let mut post_rebuild_rx = lock
            .post_rebuild_rx
            .take()
            .ok_or_else(|| anyhow::Error::msg("post_rebuild_rx has already been taken"))?;
        drop(lock);

        let loser_poller = async move {
            let mut ticker = citadel_io::tokio::time::interval(Duration::from_millis(100));
            loop {
                ticker.tick().await;

                if let Some((local_id, peer_id)) = *commanded_winner.lock().await {
                    log::trace!(target: "citadel", "Local {local_id:?} has been commanded to use {peer_id:?}");
                    let receivers = kill_signal_tx.send((local_id, peer_id)).unwrap_or(0);
                    log::trace!(target: "citadel", "Sent kill signal to {receivers} hole-punchers");

                    let mut current_enqueued_set = current_enqueued_set.lock().await;
                    'pop: while let Some(current_enqueued) = current_enqueued_set.pop() {
                        log::trace!(target: "citadel", "Maybe grabbed the currently enqueued local socket {:?}: {:?}", current_enqueued.local_id, current_enqueued.addr);
                        if current_enqueued.addr.unique_id != peer_id {
                            log::trace!(target: "citadel", "Cannot use the enqueued socket since ID does not match");
                            continue 'pop;
                        }

                        return Ok(current_enqueued);
                    }

                    drop(current_enqueued_set);

                    let mut lock = rebuilder.lock().await;
                    if let Some(failure) = lock.local_failures.get_mut(&local_id) {
                        log::trace!(target: "citadel", "[Rebuild] While searching local_failures, found match");
                        if let Some(rebuilt) =
                            failure.recovery_mode_generate_socket_by_remote_id(peer_id)
                        {
                            return Ok(rebuilt);
                        } else {
                            log::warn!(target: "citadel", "[Rebuild] Found in local_failures, but, failed to find rebuilt socket");
                        }
                    }

                    if lock.local_failures.len() == hole_puncher_count {
                        return Err(anyhow::Error::msg("All hole-punchers have failed (t1)"));
                    }
                }
            }
        };

        let loser_rebuilder_task = async move {
            log::trace!(target: "citadel", "*** Will now await post_rebuild_rx ... {} have finished", finished_count.lock());
            // Note: if properly implemented, the below should return almost instantly
            loop {
                let result = post_rebuild_rx.recv().await;
                log::trace!(target: "citadel", "*** [rebuild] Received signal {result:?}");
                match result {
                    None => return Err(anyhow::Error::msg("post_rebuild_rx failed")),

                    Some(None) => {
                        let fail_count = rebuilder.lock().await.local_failures.len();
                        log::trace!(target: "citadel", "*** [rebuild] So-far, {fail_count}/{hole_puncher_count} have finished");
                        if fail_count == hole_puncher_count {
                            return Err(anyhow::Error::msg("All hole-punchers have failed (t2)"));
                        }
                    }

                    Some(Some(res)) => {
                        log::trace!(target: "citadel", "*** [rebuild] complete");
                        return Ok(res);
                    }
                }
            }
        };

        let hole_punched_socket_res = select_ok([
            Box::pin(loser_poller)
                as Pin<Box<dyn Send + Future<Output = Result<HolePunchedUdpSocket, _>>>>,
            Box::pin(loser_rebuilder_task),
        ])
        .await
        .map(|res| res.0);

        match hole_punched_socket_res {
            Err(err) => {
                // The only way an error can occur is if the total number of failures is equal to the number of hole-punchers
                // In this case, while remote claimed a winner, we were unable to create/find the winner (this should be unreachable)
                log::error!(target: "citadel", "Rebuilder task failed. Please contact developers on Github: {err:?}");
                set_failure_occurred().await
            }

            Ok(hole_punched_socket) => {
                log::trace!(target: "citadel", "Selecting socket: {hole_punched_socket:?}");
                let _ = hole_punched_socket.cleanse();
                submit_final_candidate(hole_punched_socket)?;
                signal_done()
            }
        }
    };

    let futures_resolver = async move {
        while let Some(res) = futures.next().await {
            *finished_count.lock() += 1;

            let (res, hole_puncher) = match res {
                Ok(res) => res,
                Err(err) => {
                    log::warn!(target: "citadel", "Hole-puncher task failed: {err:?}");
                    continue;
                }
            };

            log::trace!(target: "citadel", "[Future resolver loop] Received {res:?}");

            match res {
                Ok(socket) => {
                    let peer_unique_id = socket.addr.unique_id;
                    let local_id = hole_puncher.get_unique_id();
                    current_enqueued_set.lock().await.push(socket);

                    if let Some((required_local, required_remote)) = *commanded_winner.lock().await
                    {
                        log::trace!(target: "citadel", "*** [Future resolver loop] Commanded winner (skipping NetMutex acquisition): {required_local:?}, {required_remote:?}. Will require rebuilder task to return the valid socket ...");
                        continue;
                    }

                    // NOTE: stopping here causes all pending futures from no longer being called
                    // future: if this node gets here, and waits for the mutex to drop from the other end,
                    // the other end may say that the current result is valid, but, be unaccessible since
                    // we are blocked waiting for the mutex. As such, we need to set the enqueued field
                    log::trace!(target: "citadel", "*** [Future resolver loop] Acquiring NetMutex ....");
                    let Ok(mut net_lock) = net_mutex.lock().await else {
                        log::trace!(target: "citadel", "*** [Future resolver loop] Mutex failed to acquire. Likely dropped. Will continue ...");
                        continue;
                    };

                    log::trace!(target: "citadel", "*** [Future resolver loop] Mutex acquired. Local = {local_id:?}, Remote = {peer_unique_id:?}");
                    if let Some((local, remote)) = *net_lock {
                        log::trace!(target: "citadel", "*** The Mutex is already set! Will not claim winner status ...");
                        *commanded_winner.lock().await = Some((local, remote));
                        if local_id == local && peer_unique_id == remote {
                            log::trace!(target: "citadel", "*** [Future resolver loop] The received socket *IS* the socket remote requested. Will wait for background rebuilder to finish ...");
                        } else {
                            log::trace!(target: "citadel", "*** [Future resolver loop] The received socket *is NOT* the socket remote requested. Will wait for background rebuilder to finish ...");
                        }
                    } else {
                        // We are the winner
                        log::trace!(target: "citadel", "*** Local won! Will command other side to use ({peer_unique_id:?}, {local_id:?})");
                        // Tell the other side we won, that way the rebuilder background process for the other
                        // side can respond. If we don't send this message, then, it's possible hanging occurs
                        // on the loser end because the winner combo isn't obtained until this futures
                        // resolver received a completed future; since in variable NAT setups, the adjacent side may fail
                        // entirely, it could never finish, thus never trigger the code that sets the commanded_winner
                        // and thus prompts the background code to return the socket on the adjacent node.
                        send(
                            DualStackCandidateSignal::Winner(peer_unique_id, local_id),
                            conn_tx,
                        )
                        .await?;
                        while let Some(socket) = current_enqueued_set.lock().await.pop() {
                            if socket.local_id != local_id {
                                log::warn!(target: "citadel", "*** Winner: socket ID mismatch. Expected {local_id:?}, got {:?}. Looping ...", socket.local_id);
                                continue;
                            }

                            *net_lock = Some((peer_unique_id, local_id));
                            let _ = socket.cleanse();
                            submit_final_candidate(socket)?;
                            log::trace!(target: "citadel", "*** [winner] Awaiting the signal ...");
                            drop(net_lock);
                            // the winner will drop once the adjacent node sends a WinnerCanEnd signal
                            //winner_can_end_rx.await?;
                            log::trace!(target: "citadel", "*** [winner] received the signal");
                            return signal_done();
                        }

                        unreachable!("Winner did not find any enqueued sockets. This is a developer bug. Please report this issue to github");
                    }
                }

                Err(FirewallError::Skip) => {
                    log::trace!(target: "citadel", "Rebuilt socket; Will not add to failures")
                }

                Err(err) => {
                    log::warn!(target: "citadel", "[non-terminating] Hole-punch for local bind addr {:?} failed: {:?}", hole_puncher.get_unique_id(), err);
                    let fail_count = {
                        let mut lock = rebuilder.lock().await;
                        let _ = lock
                            .local_failures
                            .insert(hole_puncher.get_unique_id(), hole_puncher);
                        lock.local_failures.len()
                    };

                    if fail_count == hole_puncher_count {
                        // All failed locally, but, remote may claim that it has a valid socket/
                        // Run the function below to exit if remote already set_failure_occurred
                        log::warn!(target: "citadel", "All hole-punchers have failed locally");
                        set_failure_occurred().await?;
                    }
                }
            }
        }

        log::trace!(target: "citadel", "Finished polling all futures");
        Ok(())
    };

    let reader = async move {
        let mut conn_rx = conn_rx.lock().await;
        loop {
            match receive(&mut conn_rx).await? {
                DualStackCandidateSignal::Winner(local_id, peer_id) => {
                    log::trace!(target: "citadel", "[READER] Remote commanded local to use peer={peer_id:?} and local={local_id:?}");
                    *commanded_winner.lock().await = Some((local_id, peer_id));
                }
                DualStackCandidateSignal::AllFailed => {
                    // All failed locally, but, remote may claim that it has a valid socket/
                    // Run the function below to exit if remote already set_failure_occurred
                    log::warn!(target: "citadel", "Remote claims all hole punchers failed");
                    set_failure_occurred().await?;
                    // If we reach here, it implies this node is still resolving futures. Do not return
                    // until the other joined future resolves itself
                }

                DualStackCandidateSignal::WinnerCanEnd => {
                    /*winner_can_end_tx.send(()).map_err(|_| {
                        anyhow::Error::msg("Unable to send through winner_can_end_tx")
                    })?;*/
                    return Ok::<_, anyhow::Error>(());
                }
            }
        }
    };

    log::trace!(target: "citadel", "[DualStack] Executing hole-puncher ....");
    let sender_reader_combo = async move {
        let res = futures::future::select_ok([
            Box::pin(futures_resolver)
                as Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send>>,
            Box::pin(reader),
        ])
        .await;
        if let Some(err) = res.as_ref().err() {
            log::warn!(target: "citadel", "Both reader/resolver futures failed: {err:?}")
        }

        // Just wait for the background process to finish up
        futures::future::pending().await
    };

    citadel_io::tokio::select! {
        _res0 = sender_reader_combo => {
            log::trace!(target: "citadel", "[DualStack] Sender/Reader combo finished");
        },
        res1 = done_rx => {
            log::trace!(target: "citadel", "[DualStack] Done signal received {res1:?}");
            res1?
        },
        res2 = loser_rebuilder_task => {
            log::trace!(target: "citadel", "[DualStack] Loser rebuilder task finished {res2:?}");
            res2?
        }
    }

    if commanded_winner.lock().await.is_none() {
        // We are the "winner"
        log::trace!(target: "citadel", "Winner: awaiting WinnerCanEnd signal");
        let mut conn_rx = conn_rx.lock().await;
        let signal = receive(&mut conn_rx).await?;
        if let DualStackCandidateSignal::WinnerCanEnd = signal {
            log::trace!(target: "citadel", "Received WinnerCanEnd signal");
        } else {
            log::warn!(target: "citadel", "Received unexpected signal: {signal:?}");
        }
    } else {
        // We are the "loser"
        log::trace!(target: "citadel", "Loser: sending WinnerCanEnd signal");
        send(DualStackCandidateSignal::WinnerCanEnd, conn_tx).await?;
    }

    log::trace!(target: "citadel", "*** ENDING DualStack ***");

    let sock = final_candidate_rx.await?;
    let _ = sock.cleanse();

    Ok(sock)
}

async fn send(
    input: DualStackCandidateSignal,
    conn: &ChannelSendHalf<DualStackCandidateSignal, MultiplexedConn>,
) -> Result<(), anyhow::Error> {
    conn.send_item(input).await
}

async fn receive(
    conn: &mut ChannelRecvHalf<DualStackCandidateSignal, MultiplexedConn>,
) -> Result<DualStackCandidateSignal, anyhow::Error> {
    conn.recv()
        .await
        .ok_or_else(|| anyhow::Error::msg("recv from bichannel failed: stream ended"))?
}
