/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

//SAAQ: Semi-Active Anti-Quantum HyperEncryption
/*
    The algorithm is innately anti-quantum due to the distortion in pure randomness.
    Whereas purely quantum-based randomness approaches 50/50 randomness, SAAQ's convergence
    is random. It may be 50/50, it may be 40/60, 45/55, 20/80, etc. Furthermore, there is 5D
    scattering of a packet's virtual coordinates.

    The algorithm is innately semi-active sense it only activates ones the user engages in
    message passing.
*/

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::Future;
use futures::future::Executor;
use futures::stream::Stream;
use mut_static::MutStatic;
use parking_lot::Mutex;
use reqwest::Client;
use tokio::timer::Interval;
use tokio_core::reactor::Remote;

use hyxe_util::HyxeError;

use crate::hyxewave::encrypt::Drill::{DrillUpdateObject, generate_port_combos, generate_total_drill_async, Toolset};
use crate::hyxewave::misc::{{Constants::{SAAQ_UPDATE_RATE_MS, Flags}}, Constants};
use crate::hyxewave::misc::Utility::{printf_err, printf_success};
use crate::hyxewave::network::Packet::Packet;
use crate::hyxewave::network::PacketGenerator::generate_coms_packet;
use crate::hyxewave::network::PacketProcessor::PacketSubtype;
use crate::hyxewave::network::session::{NetworkAccount::NetworkAccount, SessionHandler::*};

pub fn saaq_client(mut checker: SessionChecker, remote: Remote, session: HyxeObject<Session>, nac: HyxeObject<NetworkAccount>) -> impl Future<Item=(), Error=()> {
    let remote0 = remote.clone();
    let remote1 = remote.clone();

    let nac0 = Arc::clone(&nac);

    let session_receiver = checker.session_to_observe.lock().services.get_mut(&Constants::SERVICES::SAAQ_WORKER_CLIENT).unwrap().setup_unbounded_tx_rx_channel();
    let update_drill_flag = Flags::DRILL_UPDATE;


    session_receiver.from_err::<HyxeError>().for_each(move |signal| {
        let mut can_run = true;

        checker.execute(remote0.clone()).and_then(|result| {
            can_run = result;
            Ok(())
        });

        if !can_run {
            return HyxeError::throw("[SAAQ] Session has ended. Killing subsystem");
        }

        let nac0 = Arc::clone(&nac0);
        let coms_port = nac.lock().get_aux_ports()[0].clone();
        let port_range = nac.lock().get_port_range().clone();
        let (username, password) = nac.lock().get_credentials();
        let central_node = nac0.lock().get_central_node_ip().clone();
        let next_version = nac0.lock().get_toolset().get_latest_drill_version().unwrap() + 1;
        printf_success(format!("[SAAQ] Upgrading drill from v{} to v{}", next_version - 1, next_version));

        remote.clone().spawn(move |h| {
            generate_total_drill_async(remote1.clone(), port_range, true).and_then(move |(low, med, high, ultra, divine)| {
                let new_dou = DrillUpdateObject {
                    low,
                    med,
                    high,
                    ultra,
                    divine,
                    port_combos: generate_port_combos(port_range),
                    version: next_version,
                };

                //The client has proposed a new drill version below.
                println!("[SAAQ] Proposing new local drill...");
                let (new_drill, dou) = nac0.lock().get_toolset().propose_next_version(new_dou);

                //Now, we have to send the proposed DOU over the network. Craft a packet, and send it outbound
                if let Ok(bin) = bincode::serialize(&dou) {
                    println!("[SAAQ] Successfully serialized DOU! Preparing to notify central server");
                    // We set the `drill_version` to next_version -1, because we the data must be decrypted as the current valid model. The next version has been proposed locally, but it must now be synce'd with the server!

                    if let Some(packet) = generate_coms_packet(bin, Some(Arc::clone(&session)), Arc::clone(&nac0), &central_node, &central_node, coms_port, &username, &password, next_version - 1, Some(rand::random::<u64>()), update_drill_flag) {
                        println!("[SAAQ] Successfully generated packet");
                        nac0.lock().get_central_bridge().lock().send_packet_async(remote1.clone(), packet, Some(move |packet: Option<ProcessedInboundPacket>, remote: Remote| {
                            ///TODO: Once the EID is returned, this executes.
                            println!("[SAAQ] Received a response from the mainframe server! Checking packet for DRILL_UPDATE_STATUS");
                            if let Some(packet) = packet {
                                match *packet.get_subtype() {
                                    PacketSubtype::DRILL_UPDATE_SUCCESS => {}
                                    _ => {}
                                }
                            };

                            Ok("".to_string())
                        }));
                    }
                }

                Ok(())
            });

            Ok(())
        });

        Ok(())
    }).then(|obj| {
        ///Reguardless of the outcome above, we must reset the session's trigger
        session.clone().lock().reset_trigger();
        Ok(())
    }).map_err(|mut err| { err.printf(); })
}

pub fn get_next_drill() -> impl Future<Item=Option<DrillUpdateObject>, Error=()> {
    futures::lazy(move || {
        Ok(None)
    })
}