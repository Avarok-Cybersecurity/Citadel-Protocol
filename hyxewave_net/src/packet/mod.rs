/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use hyxe_netdata::packet::PACKET_HEADER_BYTE_COUNT;

/// The number of bytes capped per packet payload
pub const MAX_PAYLOAD_SIZE: usize = 555 - PACKET_HEADER_BYTE_COUNT;

mod bit_handler;

/// This is for sending large-data that requires 3D scrambling of ports
pub mod packet_layout;

/// Whereas stage 0 involves receiving data from the sockets and_then forwarding the data into inbound rx channels, stage 1 involves accepting data from those inbound rx channels as
/// Raw unprocessed packets and converting them into Processed packets. Then, it pushes it into stage 2
pub mod inbound;

/// This contains the subroutines for crafting unique packets (login packets, scanning packets, etc)
pub mod outbound;

/// The data reconstructor is an asynchronous stream which concatenates (typically) payloads of packets. This is particularly useful for reconstructing waves of data
pub mod data_reconstructor;

/// Contains various constants which are used for packet construction and validation
pub mod flags;

/// Contains the error types for this subdirectory
pub mod misc;

/// Contains the definitions of each packet type that is handled by the HyxeNetwork
pub mod definitions;