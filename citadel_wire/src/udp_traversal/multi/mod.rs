use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::stream::FuturesUnordered;
use futures::{Future, StreamExt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::error::FirewallError;
use crate::udp_traversal::hole_punch_config::HolePunchConfig;
use crate::udp_traversal::linear::encrypted_config_container::HolePunchConfigContainer;
use crate::udp_traversal::linear::SingleUDPHolePuncher;
use crate::udp_traversal::targetted_udp_socket_addr::HolePunchedUdpSocket;
use crate::udp_traversal::{HolePunchID, NatTraversalMethod};
use netbeam::reliable_conn::ReliableOrderedStreamToTarget;
use netbeam::sync::network_endpoint::NetworkEndpoint;
use netbeam::sync::subscription::Subscribable;
use netbeam::sync::RelativeNodeType;

/// Punches a hole using IPv4/6 addrs. IPv6 is more traversal-friendly since IP-translation between external and internal is not needed (unless the NAT admins are evil)
///
/// allows the inclusion of a "breadth" variable to allow opening multiple ports for traversing across multiple ports
pub(crate) struct DualStackUdpHolePuncher {
    // the key is the local bind addr
    future:
        Pin<Box<dyn Future<Output = Result<HolePunchedUdpSocket, anyhow::Error>> + Send + 'static>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(variant_size_differences)]
enum DualStackCandidate {
    MutexSet(HolePunchID, HolePunchID),
    WinnerCanEnd,
}

impl DualStackUdpHolePuncher {
    /// `peer_internal_port`: Required for determining the internal socket addr
    #[cfg_attr(
        feature = "localhost-testing",
        tracing::instrument(target = "citadel", skip_all, err(Debug))
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
        let addrs_to_ping: &Vec<SocketAddr> = &hole_punch_config.into_iter().collect();

        // each individual hole puncher fans-out from 1 bound socket to n many peer addrs (determined by addrs_to_ping)
        for socket in sockets {
            // TODO: ensure only *some* of the addrs in addrs_to_ping get passed (MAX 2)
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
            tokio::task::spawn(drive(hole_punchers, relative_node_type, napp))
                .await
                .map_err(|err| anyhow::Error::msg(format!("panic in hole puncher: {:?}", err)))?
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
    tracing::instrument(target = "citadel", skip_all, ret, err(Debug))
)]
async fn drive(
    hole_punchers: Vec<SingleUDPHolePuncher>,
    node_type: RelativeNodeType,
    ref app: NetworkEndpoint,
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
    let conn = &(app.initiate_subscription().await?);

    log::trace!(target: "citadel", "Initiating NetMutex ...");
    // setup a mutex for handling contentions
    let net_mutex = &(app.mutex::<Option<()>>(value).await?);

    let (final_candidate_tx, final_candidate_rx) =
        tokio::sync::oneshot::channel::<HolePunchedUdpSocket>();
    let (reader_done_tx, mut reader_done_rx) = tokio::sync::broadcast::channel::<()>(2);
    let mut reader_done_rx_3 = reader_done_tx.subscribe();

    let (ref kill_signal_tx, _kill_signal_rx) =
        tokio::sync::broadcast::channel(hole_punchers.len());
    let (ref post_rebuild_tx, post_rebuild_rx) = tokio::sync::mpsc::unbounded_channel();

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

    let rebuilder = &tokio::sync::Mutex::new(RebuildReadyContainer {
        local_failures: HashMap::new(),
        post_rebuild_rx: Some(post_rebuild_rx),
    });

    let loser_value_set = &citadel_io::Mutex::new(None);

    let mut futures = FuturesUnordered::new();
    for (kill_switch_rx, mut hole_puncher) in hole_punchers
        .into_iter()
        .map(|r| (kill_signal_tx.subscribe(), r))
    {
        futures.push(async move {
            let res = hole_puncher
                .try_method(
                    NatTraversalMethod::Method3,
                    kill_switch_rx,
                    post_rebuild_tx.clone(),
                )
                .await;
            (res, hole_puncher)
        });
    }

    let current_enqueued = &tokio::sync::Mutex::new(None);
    let finished_count = &citadel_io::Mutex::new(0);
    let hole_puncher_count = futures.len();

    // This is called to scan currently-running tasks to terminate, and, returning the rebuilt
    // hole-punched socket on completion
    let assert_rebuild_ready = |local_id: HolePunchID, peer_id: HolePunchID| async move {
        let mut lock = rebuilder.lock().await;
        // first, check local failures
        if let Some(mut failure) = lock.local_failures.remove(&local_id) {
            log::trace!(target: "citadel", "[Rebuild] While searching local_failures, found match");
            if let Some(rebuilt) = failure.recovery_mode_generate_socket_by_remote_id(peer_id) {
                return Ok(rebuilt);
            } else {
                log::warn!(target: "citadel", "[Rebuild] Found in local_failures, but, failed to find rebuilt socket");
            }
        }

        let _receivers = kill_signal_tx.send((local_id, peer_id))?;
        let mut post_rebuild_rx = lock
            .post_rebuild_rx
            .take()
            .ok_or_else(|| anyhow::Error::msg("post_rebuild_rx has already been taken"))?;
        log::trace!(target: "citadel", "*** Will now await post_rebuild_rx ... {} have finished", finished_count.lock());
        let mut count = 0;
        // Note: if properly implemented, the below should return almost instantly
        loop {
            if let Some(current_enqueued) = current_enqueued.lock().await.take() {
                log::trace!(target: "citadel", "Grabbed the currently enqueued socket!");
                return Ok(current_enqueued);
            }

            match post_rebuild_rx.recv().await {
                None => return Err(anyhow::Error::msg("post_rebuild_rx failed")),

                Some(None) => {
                    count += 1;
                    log::trace!(target: "citadel", "*** [rebuild] So-far, {}/{} have finished", count, hole_puncher_count);
                    if count == hole_puncher_count {
                        log::error!(target: "citadel", "This should not happen")
                    }
                }

                Some(Some(res)) => {
                    log::trace!(target: "citadel", "*** [rebuild] complete");
                    return Ok(res);
                }
            }
        }
    };

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let done_tx = citadel_io::Mutex::new(Some(done_tx));

    let signal_done = || -> Result<(), anyhow::Error> {
        let tx = done_tx
            .lock()
            .take()
            .ok_or_else(|| anyhow::Error::msg("signal_done has already been called"))?;
        tx.send(())
            .map_err(|_| anyhow::Error::msg("signal_done oneshot sender failed to send"))
    };

    let (winner_can_end_tx, winner_can_end_rx) = tokio::sync::oneshot::channel();

    let (futures_tx, mut futures_rx) = tokio::sync::mpsc::unbounded_channel();

    let futures_executor = async move {
        while let Some(res) = futures.next().await {
            futures_tx
                .send(res)
                .map_err(|_| anyhow::Error::msg("futures_tx send error"))?;
        }

        log::trace!(target: "citadel", "Finished polling all futures");
        Ok(reader_done_rx_3.recv().await?) as Result<(), anyhow::Error>
    };

    // the goal of the sender is just to send results as local finishes, nothing else
    let futures_resolver = async move {
        while let Some((res, hole_puncher)) = futures_rx.recv().await {
            log::trace!(target: "citadel", "[Future resolver loop] Received {:?}", res);
            *finished_count.lock() += 1;
            match res {
                Ok(socket) => {
                    let peer_unique_id = socket.addr.unique_id;
                    let local_id = hole_puncher.get_unique_id();

                    if let Some((pre_local, pre_remote)) = *loser_value_set.lock() {
                        log::trace!(target: "citadel", "*** Local did not win, and, already received a MutexSet: ({:?}, {:?})", pre_local, pre_remote);
                        if local_id == pre_local && peer_unique_id == pre_remote {
                            log::trace!(target: "citadel", "*** Local did not win, and, is currently waiting for the current value! (returning)");
                            // this implies local is already waiting for this result. Submit and finish here
                            post_rebuild_tx.send(Some(socket))?;
                        }

                        // continue to keep polling futures
                        continue;
                    }

                    // NOTE: stopping here causes all pending futures from no longer being called
                    // future: if this node gets here, and waits for the mutex to drop from the other end,
                    // the other end may say that the current result is valid, but, be unaccessible since
                    // we are blocked waiting for the mutex. As such, we need to set the enqueued field
                    *current_enqueued.lock().await = Some(socket);
                    let mut net_lock = net_mutex.lock().await?;
                    if let Some(socket) = current_enqueued.lock().await.take() {
                        if net_lock.as_ref().is_none() {
                            log::trace!(target: "citadel", "*** Local won! Will command other side to use ({:?}, {:?})", peer_unique_id, local_id);
                            *net_lock = Some(());
                            socket.cleanse()?;
                            submit_final_candidate(socket)?;
                            // Hold the mutex to prevent the other side from accessing the data. It will need to end via the other means
                            send(DualStackCandidate::MutexSet(peer_unique_id, local_id), conn)
                                .await?;
                            log::trace!(target: "citadel", "*** [winner] Awaiting the signal ...");
                            std::mem::drop(net_lock);
                            // the winner will drop once the adjacent node sends a WinnerCanEnd signal
                            winner_can_end_rx.await?;
                            log::trace!(target: "citadel", "*** [winner] received the signal");
                            return signal_done();
                        } else {
                            unreachable!(
                                "Should not happen since the winner holds the mutex until complete"
                            );
                        }
                    } else {
                        log::trace!(target: "citadel", "While looping, detected that the socket was taken")
                    }
                }

                Err(FirewallError::Skip) => {
                    log::trace!(target: "citadel", "Rebuilt socket; Will not add to failures")
                }

                Err(err) => {
                    log::warn!(target: "citadel", "[non-terminating] Hole-punch for local bind addr {:?} failed: {:?}", hole_puncher.get_unique_id(), err);
                    rebuilder
                        .lock()
                        .await
                        .local_failures
                        .insert(hole_puncher.get_unique_id(), hole_puncher);
                }
            }
        }

        // if we get here before the reader finishes, we need to wait for the reader to finish
        Ok(reader_done_rx.recv().await?) as Result<(), anyhow::Error>
        //Ok(()) as Result<(), anyhow::Error>
    };

    let reader = async move {
        loop {
            match receive::<DualStackCandidate, _>(conn).await {
                Ok(res) => {
                    return match res {
                        DualStackCandidate::MutexSet(local, remote) => {
                            log::trace!(target: "citadel", "*** received MutexSet. Will unconditionally end ...");
                            assert!(loser_value_set.lock().replace((local, remote)).is_none());
                            let hole_punched_socket = assert_rebuild_ready(local, remote).await?;
                            hole_punched_socket.cleanse()?;
                            submit_final_candidate(hole_punched_socket)?;
                            // return here. The winner must exit last
                            send(DualStackCandidate::WinnerCanEnd, conn).await?;
                            signal_done()
                        }

                        DualStackCandidate::WinnerCanEnd => {
                            winner_can_end_tx.send(()).map_err(|_| {
                                anyhow::Error::msg("Unable to send through winner_can_end_tx")
                            })?;
                            Ok(())
                        }
                    };
                }

                Err(err) => {
                    let err_msg = err.to_string();
                    log::warn!(target: "citadel", "Error while receiving: {err_msg:?}");
                    if !err_msg.contains("os error 10054") {
                        log::error!(target: "citadel", "Error will cause return");
                        return Err(err);
                    }
                }
            }
        }
    };

    log::trace!(target: "citadel", "[DualStack] Executing hole-puncher ....");
    let sender_reader_combo = futures::future::try_join(futures_resolver, reader);

    tokio::select! {
        res0 = sender_reader_combo => res0.map(|_| ())?,
        res1 = done_rx => res1?,
        res2 = futures_executor => res2?
    };

    log::trace!(target: "citadel", "*** ENDING DualStack ***");

    let sock = final_candidate_rx.await?;
    sock.cleanse()?;
    app.sync().await?;

    Ok(sock)
}

async fn send<R: Serialize, V: ReliableOrderedStreamToTarget>(
    ref input: R,
    conn: &V,
) -> Result<(), anyhow::Error> {
    Ok(conn
        .send_to_peer(&bincode2::serialize(input).unwrap())
        .await?)
}

async fn receive<T: DeserializeOwned, V: ReliableOrderedStreamToTarget>(
    conn: &V,
) -> Result<T, anyhow::Error> {
    Ok(bincode2::deserialize(&conn.recv().await?)?)
}
