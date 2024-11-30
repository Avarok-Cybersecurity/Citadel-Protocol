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
use crate::proto::endpoint_crypto_accessor::EndpointCryptoAccessor;
use crate::proto::packet_processor::primary_group_packet::get_proper_hyper_ratchet;
use std::sync::atomic::Ordering;

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
pub async fn process_keep_alive(
    session: &CitadelSession,
    packet: HdpPacket,
    header_drill_vers: u32,
) -> Result<PrimaryProcessorResult, NetworkError> {
    let session = session.clone();
    // TODO: keep alives for p2p conns
    if session.state.load(Ordering::Relaxed) != SessionState::Connected {
        log::warn!(target: "citadel", "Keep alive received, but session not connected. Dropping packet");
        return Ok(PrimaryProcessorResult::Void);
    }

    let task = async move {
        let session = &session;

        let hr = {
            let state_container = inner_state!(session.state_container);
            return_if_none!(
                get_proper_hyper_ratchet(header_drill_vers, &state_container, None),
                "Could not get proper HR [KA]"
            )
        };

        let (header, payload, _, _) = packet.decompose();

        if let Some((header, _payload, _hyper_ratchet)) =
            validation::aead::validate(hr, &header, payload)
        {
            let current_timestamp_ns = session.time_tracker.get_global_time_ns();
            let to_primary_stream = return_if_none!(
                session.to_primary_stream.clone(),
                "Primary stream not loaded"
            );
            let security_level = header.security_level.into();

            let task = {
                let accessor = EndpointCryptoAccessor::C2S(session.state_container.clone());
                // if the KA came in on time, then we pass. If it did not come-in on time, BUT, the meta expiry container is unexpired (meaning packets are coming in), then, pass
                let mut state_container = inner_mut_state!(session.state_container);
                if state_container
                    .on_keep_alive_received(header.timestamp.get(), current_timestamp_ns)
                    || !state_container.meta_expiry_state.expired()
                {
                    std::mem::drop(state_container);
                    // We no longer send the ka here since the sleeping blocked the ENTIRE task
                    const DELTA_NS: i64 = (KEEP_ALIVE_INTERVAL_MS * 1_000_000) as i64;
                    // we can no longer hold-on to the StackedRatchet due to truncation
                    // ever since creating the anti-replay attack, we can no longer withhold packets; they must be sent outbound
                    // immediately, otherwise other packets will fail, invalidating the session
                    async move {
                        citadel_io::tokio::time::sleep(Duration::from_millis(
                            KEEP_ALIVE_INTERVAL_MS,
                        ))
                        .await;
                        accessor.borrow_hr(None, |hr, _| {
                            let next_ka = packet_crafter::keep_alive::craft_keep_alive_packet(
                                hr,
                                current_timestamp_ns + DELTA_NS,
                                security_level,
                            );
                            to_primary_stream
                                .unbounded_send(next_ka)
                                .map_err(|err| NetworkError::Generic(err.to_string()))
                        })?;

                        Ok(PrimaryProcessorResult::Void)
                    }
                } else {
                    log::trace!(target: "citadel", "Invalid KEEP_ALIVE window; expired");
                    //session.session_manager.clear_session(session.implicated_cid.unwrap());
                    return Ok(PrimaryProcessorResult::EndSession(
                        "Keep alive arrived too late",
                    ));
                }
            };

            task.await
        } else {
            // timeout
            log::error!(target: "citadel", "Keep alive invalid!");
            Ok(PrimaryProcessorResult::Void)
        }
    };

    to_concurrent_processor!(task)
}
