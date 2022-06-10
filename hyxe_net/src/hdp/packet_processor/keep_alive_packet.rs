use super::includes::*;
use crate::error::NetworkError;
use std::sync::atomic::Ordering;
use crate::hdp::packet_processor::raw_primary_packet::ConcurrentProcessorTx;

/// This will handle a keep alive packet. It will automatically send a keep packet after it sleeps for a period of time
#[inline]
#[allow(unused_results, unused_must_use)]
pub fn process(session: &HdpSession, packet: HdpPacket, concurrent_processor_tx: &ConcurrentProcessorTx) -> Result<PrimaryProcessorResult, NetworkError> {
    let session = session.clone();

    if session.state.load(Ordering::Relaxed) != SessionState::Connected {
        log::warn!(target: "lusna", "Keep alive received, but session not connected. Dropping packet");
        return Ok(PrimaryProcessorResult::Void);
    }

    let task = async move {
        let ref session = session;

        let (header, payload, _, _) = packet.decompose();
        let ref cnac = {
            let state_container = inner_state!(session.state_container);
            return_if_none!(state_container.cnac.clone(), "Sess CNAC not loaded")
        };

        if let Some((header,_payload, _hyper_ratchet)) = validation::keep_alive::validate_keep_alive(cnac, &header, payload) {
            let current_timestamp_ns = session.time_tracker.get_global_time_ns();
            let to_primary_stream = return_if_none!(session.to_primary_stream.clone(), "Primary stream not loaded");
            let security_level = header.security_level.into();

            let task = {
                // if the KA came in on time, then we pass. If it did not come-in on time, BUT, the meta expiry container is unexpired (meaning packets are coming in), then, pass
                let mut state_container = inner_mut_state!(session.state_container);
                if state_container.on_keep_alive_received(header.timestamp.get(), current_timestamp_ns) || !state_container.meta_expiry_state.expired() {
                    std::mem::drop(state_container);
                    // We no longer send the ka here since the sleeping blocked the ENTIRE task
                    const DELTA_NS: i64 = (KEEP_ALIVE_INTERVAL_MS * 1_000_000) as i64;
                    // we can no longer hold-on to the HyperRatchet due to truncation
                    // ever since creating the anti-replay attack, we can no longer withhold packets; they must be sent outbound
                    // immediately, otherwise other packets will fail, invalidating the session
                    async move {
                        tokio::time::sleep(Duration::from_millis(KEEP_ALIVE_INTERVAL_MS)).await;
                        cnac.borrow_hyper_ratchet(None, |ratchet_opt| {
                            ratchet_opt.ok_or_else(|| NetworkError::InternalError("KA Ratchet not found")).and_then(|hyper_ratchet| {
                                let next_ka = hdp_packet_crafter::keep_alive::craft_keep_alive_packet(&hyper_ratchet, current_timestamp_ns + DELTA_NS, security_level);
                                to_primary_stream.unbounded_send(next_ka).map_err(|err| NetworkError::Generic(err.to_string()))
                            })
                        })?;

                        Ok(PrimaryProcessorResult::Void)
                    }
                } else {
                    log::trace!(target: "lusna", "Invalid KEEP_ALIVE window; expired");
                    //session.session_manager.clear_session(session.implicated_cid.unwrap());
                    return Ok(PrimaryProcessorResult::EndSession("Keep alive arrived too late"))
                }
            };

            return task.await;
        } else {
            // timeout
            log::error!(target: "lusna", "Keep alive invalid!");
            Ok(PrimaryProcessorResult::Void)
        }
    };

    to_concurrent_processor!(concurrent_processor_tx, task)
}
