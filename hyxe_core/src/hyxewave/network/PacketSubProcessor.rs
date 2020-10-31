/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use hyxe_util::HyxeError;

use crate::hyxewave::encrypt::HyCryptAF::decrypt_bytes;
use crate::hyxewave::misc::Utility::printf_err;
use crate::hyxewave::network::Packet::ProcessedInboundPacket;
use crate::hyxewave::network::session::{NetworkAccount, SessionHandler};
use crate::SecurityLevel;

/// Returns Some if the login is a success, else None
pub fn stage2_do_connect(packet: &mut ProcessedInboundPacket) -> Option<&mut ProcessedInboundPacket> {
    if packet.data.is_empty() {
        printf_err("[PacketSubProcessor::2 DROP] Packet data empty");
        return None;
    }

    let cid_needed_to_undrill = &packet.cid_needed_to_undrill;
    let nac = NetworkAccount::get_nac(cid_needed_to_undrill);

    if nac.is_none() {
        printf_err("[PacketSubProcessor::2 DROP] Unable to get NAC for the packet");
        return None;
    }


    let security_level_opt = SecurityLevel::from_byte(*packet.security_level_drilled);

    if security_level_opt.is_none() {
        printf_err("[PacketSubProcessor::2 DROP] Invalid security level specified!");
        return None;
    }

    let drill_version = packet.drill_version_needed_to_undrill;
    let nac = nac.unwrap();
    let drill = nac.read().get_drill(drill_version as usize);

    if drill.is_none() {
        printf_err("[PacketSubProcessor::2 DROP] Invalid drill version specified!");
        return None;
    }

    let drill = drill.unwrap();
    let decrypted_bytes = decrypt_bytes(encrypted_data, drill, &security_level, &0);
    ;
    //let password = String::from_utf8(decrypted_bytes).unwrap();

    if !nac.read().validate_password(decrypted_bytes.as_ref()) {
        return None;
    }

    Some(packet)
}

/// Here, we check to see if A) the packet belongs to a CID that is already logged-in to the current node, B) the pid and wid are valid (to prevent MITM attacks),
/// and C) we decrypt the data in the payload if conditions A) and B) are successful
pub fn stage2_validate_session_and_decrypt_packet(packet: &mut ProcessedInboundPacket) -> Option<&mut ProcessedInboundPacket> {
    let cid = packet.cid_needed_to_undrill;
    if let Some(sess) = SessionHandler::get_session_by_cid(&cid) {
        // If we get to this point, that means a session exists, but we need to ensure the packet coordinates are
        //valid
    }

    printf_err("[PacketSubProcessor::2 DROP] Packet does not belong to any valid session");
    None
}