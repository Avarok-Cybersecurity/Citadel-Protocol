/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use byteorder::{BigEndian, ReadBytesExt};
use futures::prelude::*;
use parking_lot::Mutex;
use tokio_core::reactor::Remote;

use crate::bytes::ByteOrder;
use crate::hyxewave::encrypt::HyCryptAF::*;
use crate::hyxewave::misc::Constants;
use crate::hyxewave::misc::Utility::printf_err;
use crate::hyxewave::network::Packet::{InboundPacket, Packet, PacketCoordinates, ProcessedInboundPacket};
use crate::hyxewave::network::PacketGenerator::generate_connect_rebound_packet;
use crate::hyxewave::network::PacketSubProcessor;
use crate::hyxewave::network::PacketWrapper::HYXE_HEADER_SIZE;
use crate::hyxewave::network::session::*;
use crate::hyxewave::network::SocketHandler::PacketType;
use crate::hyxewave::network::WaveformListener::WaveformListener;
use crate::SecurityLevel;

///The goal of this subroutine is to simply take the BigEndian'ed bytes and extract the values out of the InboundPacket Header.
/// This DOES NOT guarantee that the packet headers are valid... that is the goal of the next step
pub fn stage1_process_inbound_packet(packet: InboundPacket) -> Option<ProcessedInboundPacket> {
    if packet.data.len() < HYXE_HEADER_SIZE {
        eprintln!("Error parsing packet! Dropping the packet, for it is invalid!");
        return None;
    }

    let cid_initial = BigEndian::read_u64(&packet.data[0..=7]);
    let cid_needed_to_undrill = BigEndian::read_u64(&packet.data[8..=15]);
    let drill_version_needed_to_undrill = BigEndian::read_u32(&packet.data[16..=19]);
    let security_level_drilled = &packet.data[20];

    let timestamp = BigEndian::read_i64(&packet.data[21..=28]);

    let current_packet_hop_state = &packet.data[29];
    let next_hop_state = &packet.data[30];
    let endpoint_destination_type = &packet.data[31];

    let command_flag = &packet.data[32];

    let expects_response = &packet.data[33];
    let oid_eid = BigEndian::read_u64(&packet.data[34..=41]);
    let wid = BigEndian::read_f64(&packet.data[42..=49]);
    let pid = BigEndian::read_f64(&packet.data[50..=57]);

    let route_dest_nid = BigEndian::read_u64(&packet.data[58..=65]);
    let route_dest_cid = BigEndian::read_u64(&packet.data[66..=73]);

    let payload = packet.data[HYXE_HEADER_SIZE..packet.data.len()].to_vec();

    Some(ProcessedInboundPacket::craft(cid_initial, cid_needed_to_undrill, drill_version_needed_to_undrill, *security_level_drilled, timestamp, *current_packet_hop_state, *next_hop_state, *endpoint_destination_type, *command_flag, *expects_response, oid_eid, wid, pid, route_dest_nid, payload))
}

/// We validate that the packet is associated with a valid session, and then get that session and use it to decrypt the data.
/// NOTE: We can branch from here into stage2_subtypes. For example, if the packet is a CONNECT type, then there will be NO
/// SESSION associated therewith. As such, we should first check to see the packet's command_flag, then proceed with the primary
/// set of logic for stage2. Additionally, some packets may never make it past this stage, in which case, we return None herein
pub fn stage2_validate_and_decrypt_packet(packet: &mut ProcessedInboundPacket, remote: &Remote) -> Option<&mut ProcessedInboundPacket> {
    /// Check to see if we need to handle any [non-session bound] packets
    match packet.command_flag {
        Constants::Flags::DO_CONNECT => {
            PacketSubProcessor::stage2_do_connect(packet)
        }

        _ => {
            None
        }
    }
}

/// Was this packet expected? If so, execute the expectancy-closure for the packet
pub fn stage3_find_direction_and_expectation(packet: &mut ProcessedInboundPacket) -> Option<&mut ProcessedInboundPacket> {}

pub fn stage_3b(mut packet: ProcessedInboundPacket, remote: Remote) -> impl Future<Item=(), Error=()> {
    futures::lazy(move || {
        println!("[PacketProcessor-3B] Packet received!");
        let encrypted_data = &packet.data;

        let cid = packet.cid_needed_to_undrill;
        let drill_version = packet.drill_version_needed_to_undrill;
        let security_level = SecurityLevel::from_byte(*packet.security_level_drilled).unwrap();


        let amplitudal_sum = 0 as usize;
        let eid = packet.get_eid().unwrap();

        let nac = NetworkAccount::get_nac(&cid);

        if nac.is_none() {
            eprintln!("[PacketProcessor-3B] Unable to get NAC for the packet; dropping packet");
            return Ok(());
        }

        let cid = packet.get_cid();
        let nac = nac.unwrap();
        let drill = nac.lock().get_drill(drill_version).unwrap();

        let decrypted_bytes = decrypt_bytes(encrypted_data, drill, &security_level, &amplitudal_sum);

        let password = String::from_utf8(decrypted_bytes).unwrap();


        match packet.get_subtype() {
            PacketSubtype::CONNECT => {
                //decrypt the message, get the username and password, check the username and password, send response back to source
                println!("[PacketProcessor-3B] [CONNECT] Packet received");


                //set security_level as desired for the CONNECT packet:
                nac.lock().set_security_level(security_level);

                println!("[PacketProcessor-3B] [CONNECT] Decrypted bytes: {}", password);
                if !nac.lock().validate_password(&password) {
                    println!("[PacketProcessor-3B] [CONNECT] Login request FAILURE; sending failure packet to {}", packet.get_src_ip());
                    if let Some(packet) = generate_connect_rebound_packet(None, Arc::clone(&nac), packet.get_src_ip(), *packet.get_src_port(), false, None, eid) {
                        println!("[PacketProcessor-3B] [CONNECT] The processed packet will be sent to: {}", packet.get_dest_ip());
                        nac.lock().get_central_bridge().lock().send_packet_simple_sync(packet);
                        return;
                    }
                    eprintln!("[PacketProcessor-3B] [CONNECT] Unable to create rebound packet for {}", packet.get_src_ip());
                    return;
                }

                let src_ip = packet.get_src_ip();
                println!("[PacketProcessor-3B] [CONNECT] Login request SUCCESS; sending success packet to {}", src_ip);
                // In the message of the rebound packet, we want to inscribe the global IP address of the client
                if let Some(packet) = generate_connect_rebound_packet(None, Arc::clone(&nac), packet.get_src_ip(), *packet.get_src_port(), true, Some(src_ip.clone()), eid) {
                    let bridge = Arc::clone(&nac).lock().get_central_bridge();
                    println!("[PacketProcessor-3B] [CONNECT] Asserting connection to {}", packet.get_dest_ip());

                    if let Some(session) = SessionHandler::StateTransfer::on_connect_packet_received_server(Arc::clone(&nac), remote.clone(), packet.get_dest_ip().clone()) {
                        println!("[PacketProcessor-3B] [CONNECT] Server successfully transferred session state to CONNECTED");
                    } else {
                        eprintln!("[PacketProcessor-3B] [CONNECT] Server unable to transfer session state");
                    }

                    bridge.lock().send_packet_simple_sync(packet);
                    println!("[PacketProcessor-3B] [CONNECT] PROCESSING_DONE :: Sent packet to {}!", cid);
                    return;
                }

                eprintln!("[PacketProcessor-3B] [CONNECT] Unable to create rebound packet for {}", cid);
            }

            _ => {
                eprintln!("[PacketProcessor-3B] [CONNECT] Severe error! Stage 3B failed because the packet does not have a valid subtype. Dropping packet!")
            }

            PacketSubtype::MESSAGE => {
                println!("[PacketProcessor-3B] [MESSAGE] [TODO] Packet received");
            }
        }
    })
}
