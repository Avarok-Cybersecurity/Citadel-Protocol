/// § Reserved Section 10-29
pub mod connect {
    use crate::connection::server_bridge_handler::ServerBridgeHandler;
    use hyxe_netdata::packet::{StageDriverPacket, PacketStage};
    use crate::packet::flags::connect;

    /// Processes a DO_LOGIN_SUCCESS signal. This does not necessarily imply the login is 100% done, however:
    /// The IP address must be checked for purposes of enforcing [PINNED_IP_MODE] (PIM)
    pub fn do_login_success(this: &ServerBridgeHandler, mut packet: StageDriverPacket) {
        // This is step 4. We must take this packet and forward it to the sender. We will use the [BridgeHandler] created by the initiation process obtained from step [3]
        // However, we do not yet know if there exists an IP which is equal between the [BridgeHandler]'s IP and the [StageDriverPacket]. As such, we must check `this.bridges`
        let remote_sender = packet.get_sender().ip();
        if this.bridges.contains_key(&remote_sender) {
            // This is good. Now, we can safely send a DO_LOGIN_SUCCESS back to the sender, signalling it that this server is now ready to begin accepting connections.
            // however, we must update the NAC stored within the [BridgeHandler]
            let mut header = packet.get_mut_header();
            let mut bridge = this.bridges.get_mut(&remote_sender).unwrap();
            // The [StageDriver] needs to update the NID by the time the packet gets. TODO
            let nid = header.nid_original.get();
            let cid = header.cid_original.get();

            debug_assert_ne!(nid, 0, "The stage driver must transform the NID value beforehand"); // The stage driver must transform this value

            // We have to update the bridge's loaded CNAC, as well as its NAC. This subroutine automatically determines if this connection is
            // an interserver connection, and take appropriate steps to ensure the validity of such logic
            if !bridge.cxn_init_cnac(nid, cid, &remote_sender, &this.account_manager) {
                // PIM check failure
                header.command_flag = connect::DO_LOGIN_FAILURE;

            }
            // We forwarded the signal to alert the client that the login attempt was a success (or failure!)
            // Now, we must wait for the client to form a connection with the other 21 ports
            packet.clear_payload();

            let res = bridge.forward_singleton_packet(packet).is_ok();
            debug_assert!(res);
        } else {
            println!("[ServerBridgeHandler] A successful login occurred, however, this server did not expect it. Will not bother to alert the sender. Flagging packet for deletion");
            packet.stage = PacketStage::NeedsDelete;
        }
    }

    /// Processes a DO_LOGIN_FAILURE signal
    pub fn do_login_failure(this: &ServerBridgeHandler, mut packet: StageDriverPacket) {
        // This is step 4. We must take this packet and forward it to the sender. We will use the [BridgeHandler] created by the initiation process obtained from step [3]
        // However, we do not yet know if there exists an IP which is equal between the [BridgeHandler]'s IP and the [StageDriverPacket]. As such, we must check `this.bridges`
        let remote_sender = packet.get_sender().ip();
        if this.bridges.contains_key(&remote_sender) {
            let bridge = this.bridges.get(&remote_sender).unwrap();
            packet.clear_payload();
            // send the error signal back to the source
            let res = bridge.forward_singleton_packet(packet).is_ok();
            debug_assert!(res);
            // now, remove the bridge that signal has been sent. TODO: Login failure counting. Bigger TODO: Firewall
            let res = this.terminate_bridge(&remote_sender);
            debug_assert!(res);
        } else {
            println!("[ServerBridgeHandler] A unsuccessful login occurred, and, this server did not expect it. Flagging packet for deletion | TODO: Firewall");
            packet.stage = PacketStage::NeedsDelete;
        }
    }
}

/// § Reserved Section 50s
pub mod registration {
    use hyxe_netdata::packet::StageDriverPacket;
    use crate::connection::server_bridge_handler::ServerBridgeHandler;
    use crate::packet::definitions::registration::{STAGE1_SERVER, STAGE1_CLIENT, STAGE2_SERVER, STAGE2_CLIENT, STAGE3_SERVER, STAGE3_CLIENT};
    
    /// Processes any given signal
    #[allow(unused_results)]
    pub fn process_registration_signal(this: &ServerBridgeHandler, mut packet: StageDriverPacket) {
        let header = packet.get_header();

        match header.oid_eid.get() {
            STAGE1_SERVER => {
                this.registration_handler.process_stage1_server_registration_signal(packet, &this.account_manager, &this.network_map);
            },

            STAGE1_CLIENT => {

            },

            STAGE2_SERVER => {

            },

            STAGE2_CLIENT => {

            },

            STAGE3_SERVER => {

            },

            STAGE3_CLIENT => {

            },

            x => {
                eprintln!("[ServerBridgeHandler] [E] {} is an invalid registration oid_eid. Dropping packet", x);
                packet.delete();
            }
        }
    }
}