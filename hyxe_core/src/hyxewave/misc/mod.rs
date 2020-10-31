/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

pub mod Utility;
pub mod Globals;

pub mod Constants {
    use std::net::IpAddr;
    pub use std::str::FromStr;

    pub const DEFAULT_BIT_ORDER: &str = "BIG_ENDIAN";

    pub const LOCALHOST: &str = "[::]";
    pub const MAINFRAME_SERVER_IP: &str = "fe80::7a2b:cbff:fe1c:7411";

    pub const LOOPBACK_PORT: u16 = 25023;
    pub const DAEMON_PORT: u16 = 25024;
    pub const REGISTRATION_PORT: u16 = 25025;

    lazy_static! {
        pub static ref MAINFRAME_ON_LAN: bool = {
            !IpAddr::from_str(MAINFRAME_SERVER_IP).unwrap().is_global()
        };

        pub static ref ZERO_TIME_REF: Instant = Instant::new(0);
    }

    pub const VERSION: f32 = 0.01;
    pub const VERSION_STATE: &str = "alpha";

    pub const PORT_START: u16 = 25000;
    pub const PORT_END: u16 = 25020;
    pub const AUX_PORTS: [u16; 2] = [25020, 25021];

    pub const SERVER_INST: i32 = 0;
    pub const CLIENT_INST: i32 = 1;

    pub const IP_PROTOCOL: i32 = 6;
    //or 4 (make sure to change value in kcp-rs/src/kcp.rs:295
    pub const MAX_PACKET_SIZE_BYTES: i32 = 500;
    //MTU (max transmission unit) is usually set at 1500, but some networks have a lower limit of ~555. Set below for assurance of delivery
    pub const MIN_PACKET_PAYLOAD_SIZE: usize = 50;

    pub const TIMEOUT: usize = 3000;
    pub const MAX_PING_FAILS: usize = 3;
    pub const BACKGROUND_CHECK_DELAY: usize = 5000;

    pub const SAAQ_UPDATE_RATE_MS: usize = 500;

    pub mod PacketConfigurations {
        pub const IPV6_EID_INDEX: usize = 0;
        pub const YES_IPV6_AND_YES_EID: u8 = 10;
        pub const YES_IPV6_AND_NO_EID: u8 = 11;
        pub const NO_IPV6_AND_YES_EID: u8 = 12;
        pub const NO_IPV6_AND_NO_EID: u8 = 13;

        pub const COORDINATES_SPECIFIER_INDEX: usize = 1;
        pub const YES_COORDINATES: u8 = 14;
        pub const NO_COORDINATES: u8 = 15;
    }

    pub mod Flags {
        pub const DO_CONNECT: u8 = 100;
        pub const DO_CONNECT_FAILURE: u8 = 101;
        pub const DO_CONNECT_SUCCESS: u8 = 102;

        pub const DO_RECONNECT: u8 = 103;

        pub const KEEP_ALIVE: u8 = 110;

        pub const DO_DISCONNECT: u8 = 111;
        pub const DO_DISCONNECT_SUCCESS: u8 = 112;
        pub const DO_DISCONNECT_FAILURE: u8 = 113;

        pub const MESSAGE: u8 = 114;
        //3D data packet (no v_time, z_time) = (pid, wid, oid)
        pub const D5: u8 = 115; //5D data packet (pid, wid, v_time, z_time, oid)

        pub const LINEAR_MESSAGE: u8 = 130;
        pub const PACKET_COLUMN_HEADER: u8 = 131;
        pub const OBJECT_HEADER: u8 = 132;
        pub const IP_TABLE_UPDATE: u8 = 133;

        pub const DRILL_UPDATE: u8 = 140;
        pub const DRILL_UPDATE_ACK_SUCCESS: u8 = 141;
        pub const DRILL_UPDATE_ACK_FAILURE: u8 = 142;

        pub const ROUTE_TO_HYPERLAN: u8 = 150;
        pub const ROUTE_TO_HYPERWAN_CLIENT: u8 = 151;
        pub const ROUTE_TO_HYPERWAN_SERVER: u8 = 152;
    }

    pub mod DAEMON_COMMANDS {
        pub const DO_CONNECT: &str = "CONNECT";
        pub const DO_CONNECT_SUCCESS: &str = "CONNECT_SUCCESS";
        pub const DO_CONNECT_FAILURE: &str = "CONNECT_FAILURE";

        pub const DO_KEEP_ALIVE_SUCCESS: &str = "KEEP_ALIVE_SUCCESS";
        pub const DO_KEEP_ALIVE_FAILURE: &str = "KEEP_ALIVE_FAILURE";

        pub const DO_DISCONNECT: &str = "DISCONNECT";
        pub const DO_DISCONNECT_SUCCESS: &str = "DISCONNECT_SUCCESS";
        pub const DO_DISCONNECT_FAILURE: &str = "DISCONNECT_FAILURE";

        pub const DO_SEND_MESSAGE: &str = "SEND_MESSAGE";
        pub const DO_SEND_MESSAGE_SUCCESS: &str = "SEND_MESSAGE_SUCCESS";
        pub const DO_SEND_MESSAGE_FAILURE: &str = "SEND_MESSAGE_FAILURE";

        pub const DO_SEND_FILE: &str = "SEND_FILE";
        pub const DO_SEND_FILE_SUCCESS: &str = "SEND_FILE_SUCCESS";
        pub const DO_SEND_FILE_FAILURE: &str = "SEND_FILE_FAILURE";

        pub const DO_CONFIRM_RECEIVE_FILE: &str = "CONFIRM_RECEIVE_FILE";
        pub const DO_CONFIRM_RECEIVE_FILE_SUCCESS: &str = "CONFIRM_RECEIVE_FILE_SUCCESS";
        pub const DO_CONFIRM_RECEIVE_FAILURE: &str = "CONFIRM_RECEIVE_FILE_FAILURE";
    }

    pub mod SERVICES {
        pub const CONNECTION_WORKER: usize = 0;
        //Sends keep-alives from client to server
        pub const SERVER_CONNECTION_WORKER: usize = 1; //Keeps tally of the connection validity

        pub const SAAQ_WORKER_CLIENT: usize = 2;
        pub const SAAQ_WORKER_SERVER: usize = 3;
    }

    pub const BYTE_STRETCH: [usize; 5] = [1, 2, 4, 8, 16];

    /// For debugging purposes, we will set the maximum number of drill-uses to 1000 before the toolset must upgrade the drill
    /// We will set this lower once the wave-system is fully debugged. Then, we can work on debugging the SAAQ system
    pub const MAX_DRILL_TRIGGERS: usize = 1000;
}