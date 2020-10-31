use crate::prelude::{RawInboundItem, flags};
use crate::packet::flags;
use hyxe_user::client_account::ClientNetworkAccount;
use secstr::SecVec;
use hyxe_crypt::decrypt::HyperDecryptor;
use hyxe_crypt::drill::SecurityLevel;
use crate::packet::misc::StageError;
use hyxe_netdata::packet::StageDriverPacket;
use crate::packet::flags::connect::{DO_LOGIN_SUCCESS, DO_LOGIN_FAILURE};


/// There are several necessary steps this must perform. First, we must assert the packet received
/// is indeed a login type. We can do debug asserts for this.
///
/// The payload for a login packet is the username, comma, password. All three elements are concatenated
/// and then encrypted together
pub fn stage2_check_credentials(mut packet: StageDriverPacket, cnac: &ClientNetworkAccount) -> Result<(), StageError> {
    let header = packet.get_header();
    let read = cnac.read();
    debug_assert!(packet_needs_credential_check(header.command_flag));


    let drill_version = header.drill_version_needed_to_undrill.get();
    let security_level = SecurityLevel::for_value(header.security_level_drilled as usize)?;
    let drill = read.toolset.get_drill(drill_version)?;

    let decrypted_expr = drill.decrypt_to_vec(packet.get_payload(), 0, security_level)?;

    if !decrypted_expr.contains(&b',') {
        return Err(StageError::Stage1("Comma missing from login expression".to_string()))
    }

    let (username_unencrypted, password_unencrypted) = decrypted_expr.split_str(",").collect_tuple::<(&[u8], &[u8])>()?;

    let password_decrypted = SecVec::from(password_unencrypted);

    match read.validate_password(username_unencrypted, password_decrypted) {
        Ok(_) => {
            packet.get_mut_header().command_flag = DO_LOGIN_SUCCESS;
            Ok(())
        },

        Err(err) => {
            packet.get_mut_header().command_flag = DO_LOGIN_FAILURE;
            Err(StageError::Stage1(err.to_string()))
        }
    }
}

pub(super) fn packet_needs_credential_check(flag: u8) -> bool {
    flag == flags::connect::DO_LOGIN
}