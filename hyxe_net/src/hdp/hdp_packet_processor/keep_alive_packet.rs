use std::hint::black_box;

use super::includes::*;

/// This will handle a keep alive packet. It will automatically send a keep packet after it sleeps for a period of time
#[inline]
#[allow(unused_results)]
pub fn process(session: &HdpSession, packet: HdpPacket) -> PrimaryProcessorResult {
    let session = inner!(session);

    if session.state != SessionState::Connected {
        log::error!("Keep alive received, but session not connected. Dropping packet");
        return PrimaryProcessorResult::Void;
    }

    let (header, payload, _, _) = packet.decompose();
    let cnac = session.cnac.as_ref()?;
    let pqc = session.post_quantum.clone()?;

    if let Some((header,_payload, drill)) = validation::keep_alive::validate_keep_alive(cnac, &pqc, &header, payload) {
        let current_timestamp_ns = session.time_tracker.get_global_time_ns();
        let to_primary_stream = session.to_primary_stream.clone()?;
        let mut state_container = inner_mut!(session.state_container);
        if state_container.on_keep_alive_received(header.timestamp.get(), current_timestamp_ns) {
            // We no longer send the ka here since the sleeping blocked the ENTIRE task
            const DELTA_NS: i64 = (KEEP_ALIVE_INTERVAL_MS * 1_000_000) as i64;
            // get the next version, or, just use the one already supplied
            let drill = cnac.get_drill(Some(drill.get_version().wrapping_add(1))).unwrap_or(drill);
            spawn!(async move {
                    // ever since creating the anti-replay attack, we can no longer withold packets; they must be sent outbound
                    // immediately, otherwise other packets will fail, invalidating the session
                    tokio::time::delay_for(Duration::from_millis(KEEP_ALIVE_INTERVAL_MS)).await;
                    let next_ka = hdp_packet_crafter::keep_alive::craft_keep_alive_packet(&drill, &pqc, current_timestamp_ns + DELTA_NS);
                    if let Err(_) = to_primary_stream.unbounded_send(next_ka) {
                        black_box(())
                    }
                });

            PrimaryProcessorResult::Void
        } else {
            log::trace!("Invalid KEEP_ALIVE window; expired");
            //session.session_manager.clear_session(session.implicated_cid.unwrap());
            PrimaryProcessorResult::EndSession("Keep alive arrived too late")
        }
    } else {
        // timeout
        log::error!("Keep alive invalid!");
        PrimaryProcessorResult::Void
    }
}
