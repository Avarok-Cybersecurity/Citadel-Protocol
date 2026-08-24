//! The two long-lived tasks behind every UDP subsystem: the inbound datagram listener and the
//! outbound sealer. Platform-independent (native sockets, QUIC datagrams, WebRTC DataChannels).

use crate::constants::{UDP_OUTBOUND_DRAIN_BATCH, UDP_OUTBOUND_MAX_QUEUED};
use crate::error::NetworkError;
use crate::proto::endpoint_crypto_accessor::EndpointCryptoAccessor;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::misc::udp_internal_interface::UdpStream;
use crate::proto::outbound_sender::{UdpQueueItem, UnboundedReceiver};
use crate::proto::packet_crafter::udp::craft_udp_packet;
use crate::proto::session::CitadelSession;
use bytes::Bytes;
use citadel_crypt::ratchets::Ratchet;
use citadel_io::tokio::sync::mpsc::error::TryRecvError;
use citadel_io::{error, ErrorCode};
use citadel_wire::udp_traversal::hole_punched_socket::TargettedSocketAddr;
use futures::{SinkExt, StreamExt};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub(crate) async fn listen_udp_port<R: Ratchet, T: PlatformOps, S: UdpStream>(
    this: CitadelSession<R, T>,
    _hole_punched_addr_ip: std::net::IpAddr,
    local_port: u16,
    mut stream: S,
    peer_session_accessor: EndpointCryptoAccessor<R>,
) -> Result<(), NetworkError> {
    use crate::proto::packet::HdpPacket;

    while let Some(res) = stream.next().await {
        match res {
            Ok((packet, remote_peer)) => {
                log::trace!(target: "citadel", "Packet received on port {} has {} bytes (src: {:?})", local_port, packet.len(), remote_peer);
                let packet = HdpPacket::new_recv(packet, remote_peer, local_port);
                this.process_inbound_packet_udp(packet, &peer_session_accessor)?;
            }
            Err(err) => {
                log::warn!(target: "citadel", "UDP Stream error: {err:#?}");
                break;
            }
        }
    }

    log::trace!(target: "citadel", "Ending UDP Port listener on {local_port}");
    Ok(())
}

/// Outbound sealer. Wakes on the first queued payload, pulls everything immediately available
/// into a local queue capped at `UDP_OUTBOUND_MAX_QUEUED` (oldest dropped beyond that: real-time
/// data prefers fresh frames; `dropped` counts them), then seals `UDP_OUTBOUND_DRAIN_BATCH`
/// payloads per crypto-state borrow, feeds each datagram to the sink and flushes once per batch.
/// A per-datagram failure (oversized, unsupported level) is logged and skipped; only a dead
/// sink or a closed receiver ends the task.
pub(crate) async fn udp_outbound_sender<
    R: Ratchet,
    S: SinkExt<Bytes, Error = NetworkError> + Unpin,
>(
    mut receiver: UnboundedReceiver<UdpQueueItem>,
    hole_punched_addr: TargettedSocketAddr,
    mut sink: S,
    peer_session_accessor: EndpointCryptoAccessor<R>,
    dropped: Arc<AtomicU64>,
) -> Result<(), NetworkError> {
    let target_cid = peer_session_accessor.get_target_cid();
    let send_addr = hole_punched_addr.send_address;
    let mut pending: VecDeque<UdpQueueItem> = VecDeque::with_capacity(UDP_OUTBOUND_DRAIN_BATCH);
    let mut sealed: Vec<Bytes> = Vec::with_capacity(UDP_OUTBOUND_DRAIN_BATCH);
    let mut receiver_open = true;

    loop {
        if pending.is_empty() {
            if !receiver_open {
                break;
            }
            match receiver.recv().await {
                Some(first) => pending.push_back(first),
                None => break,
            }
        }
        if receiver_open {
            receiver_open = pull_available(&mut receiver, &mut pending, &dropped);
        }

        let take = pending.len().min(UDP_OUTBOUND_DRAIN_BATCH);
        peer_session_accessor.borrow_hr(None, |hr, _| {
            for (cmd_aux, level, payload) in pending.drain(..take) {
                match craft_udp_packet(hr, cmd_aux, payload, target_cid, level) {
                    Ok(packet) => sealed.push(packet.freeze()),
                    Err(err) => log::warn!(target: "citadel", "Dropping UDP payload: {err}"),
                }
            }
        })?;

        for packet in sealed.drain(..) {
            log::trace!(target: "citadel", "About to send packet w/len {} | Dest: {:?}", packet.len(), send_addr);
            match sink.feed(packet).await {
                Ok(()) => {}
                Err(err) if err.code() == ErrorCode::UdpDatagramTooLarge => {
                    log::warn!(target: "citadel", "Dropping UDP datagram: {err}");
                }
                Err(_) => return Err(error!(ErrorCode::UdpSinkRecvFailed)),
            }
        }
        sink.flush()
            .await
            .map_err(|_| error!(ErrorCode::UdpSinkRecvFailed))?;
    }

    log::trace!(target: "citadel", "Outbound wave sender ending");
    Ok(())
}

/// Moves every immediately-available payload into `pending`, evicting the oldest once the
/// queue exceeds `UDP_OUTBOUND_MAX_QUEUED`. Returns `false` once the sender side is gone.
fn pull_available(
    receiver: &mut UnboundedReceiver<UdpQueueItem>,
    pending: &mut VecDeque<UdpQueueItem>,
    dropped: &AtomicU64,
) -> bool {
    let mut evicted = 0u64;
    let open = loop {
        match receiver.try_recv() {
            Ok(item) => {
                pending.push_back(item);
                if pending.len() > UDP_OUTBOUND_MAX_QUEUED {
                    pending.pop_front();
                    evicted += 1;
                }
            }
            Err(TryRecvError::Empty) => break true,
            Err(TryRecvError::Disconnected) => break false,
        }
    };
    if evicted > 0 {
        dropped.fetch_add(evicted, Ordering::Relaxed);
        log::warn!(target: "citadel", "UDP outbound queue over budget; dropped {evicted} oldest datagrams");
    }
    open
}
