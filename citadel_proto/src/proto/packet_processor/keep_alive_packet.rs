//! # Keep-Alive Packet Processor
//!
//! Implements connection maintenance through periodic keep-alive packets,
//! ensuring connections remain active and detecting disconnections early.
//!
//! ## Features
//!
//! - **Connection Maintenance**:
//!   - Periodic heartbeat packets
//!   - Connection liveness detection
//!   - Timeout management
//!   - Automatic reconnection triggers
//!
//! - **State Management**:
//!   - Connection state tracking
//!   - Latency monitoring
//!   - Jitter calculation
//!   - Connection quality metrics
//!
//! ## Important Notes
//!
//! - Configurable keep-alive intervals
//! - Adaptive timing based on network conditions
//! - Minimal bandwidth overhead
//! - Handles both UDP and TCP connections
//!
//! ## Related Components
//!
//! - [`connect_packet`]: Connection establishment
//! - [`disconnect_packet`]: Connection termination
//! - [`session_manager`]: Session management
//! - [`udp_internal_interface`]: UDP transport

use super::includes::*;
use crate::error::NetworkError;
use crate::proto::misc::platform_ops::PlatformOps;
use crate::proto::packet_processor::primary_group_packet::get_orientation_safe_ratchet;
use citadel_crypt::ratchets::Ratchet;

/// This will handle a keep alive packet. It will automatically send a keep packet after it sleeps for a period of time
#[allow(unused_results, unused_must_use)]
#[cfg_attr(feature = "localhost-testing", tracing::instrument(
    level = "trace",
    target = "citadel",
    skip_all,
    ret,
    err,
    fields(is_server = session.is_server, src = packet.parse().unwrap().0.session_cid.get(), target = packet.parse().unwrap().0.target_cid.get()
    )
))]
pub async fn process_keep_alive<R: Ratchet, T: PlatformOps>(
    session: &CitadelSession<R, T>,
    packet: HdpPacket,
    header_entropy_bank_vers: u32,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session = session.clone();
    // TODO: keep alives for p2p conns
    if !session.state.is_connected() {
        log::warn!(target: "citadel", "Keep alive received, but session not connected. Dropping packet");
        return Ok(PrimaryProcessorResult::Void);
    }

    let task = async move {
        let session = &session;

        let hr = {
            let state_container = inner_state!(session.state_container);
            return_if_none!(
                get_orientation_safe_ratchet(header_entropy_bank_vers, &state_container, None),
                "Could not get proper HR [KA]"
            )
        };

        let (header, payload, _, _) = packet.decompose();

        if let Some((header, _payload, ratchet)) = validation::aead::validate(hr, &header, payload)
        {
            if super::server_probe_packet::is_probe(header.cmd_aux) {
                return super::server_probe_packet::process(
                    session,
                    header.cmd_aux,
                    header.context_info.get(),
                    &ratchet,
                    header.security_level.into(),
                );
            }
            let current_timestamp_ns = session.time_tracker.get_global_time_ns();
            let to_primary_stream = return_if_none!(
                session.to_primary_stream.clone(),
                "Primary stream not loaded"
            );
            let security_level = header.security_level.into();

            // if the KA came in on time, then we pass. If it did not come-in on time, BUT, the meta expiry container is unexpired (meaning packets are coming in), then, pass
            let mut state_container = inner_mut_state!(session.state_container);
            if state_container.on_keep_alive_received(header.timestamp.get(), current_timestamp_ns)
                || !state_container.meta_expiry_state.expired()
            {
                // The reply waits one interval on the session's queue worker, not in this
                // inbound slot, and at most one is pending.
                if state_container.claim_keep_alive_reply() {
                    std::mem::drop(state_container);
                    const DELTA_NS: i64 = (KEEP_ALIVE_INTERVAL_MS * 1_000_000) as i64;
                    session.queue_handle.insert_oneshot(
                        Duration::from_millis(KEEP_ALIVE_INTERVAL_MS),
                        move |state_container| {
                            state_container.send_keep_alive_reply(
                                &to_primary_stream,
                                current_timestamp_ns + DELTA_NS,
                                security_level,
                            )
                        },
                    );
                } else {
                    log::trace!(target: "citadel", "A keep-alive reply is already pending; this keep-alive schedules none");
                }
                Ok(PrimaryProcessorResult::Void)
            } else {
                log::trace!(target: "citadel", "Invalid KEEP_ALIVE window; expired");
                Ok(PrimaryProcessorResult::EndSession(
                    "Keep alive arrived too late",
                ))
            }
        } else {
            // timeout
            log::error!(target: "citadel", "Keep alive invalid!");
            Ok(PrimaryProcessorResult::Void)
        }
    };

    to_concurrent_processor!(task)
}
