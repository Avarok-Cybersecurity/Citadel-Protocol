/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use core::borrow::{Borrow, BorrowMut};
use std::cell::{RefCell, UnsafeCell};
use std::net::{IpAddr, SocketAddr};
use std::ptr::{NonNull, Unique};
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::thread::{sleep, sleep_ms};
use std::time::Duration;

use bytes::Bytes;
use futures::future::{JoinAll, Shared};
use futures::future::Either;
use futures::sync::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::sync::mpsc;
use futures::task::Task;
use hashbrown::HashMap;
use parking_lot::Mutex;
use rayon::*;
use tokio::io::Error;
use tokio::prelude::future::{Executor, Future, IntoFuture};
use tokio::prelude::stream::Stream;
use tokio::sync::watch;
use tokio_core::reactor::{Core, Handle, Remote};

use hyxe_util::HyxeError;
use tokio_kcp::KcpSessionManager;
use tokio_kcp::KcpSessionOperation;
use tokio_kcp::KcpSessionUpdater;

use crate::HyxeObject;
use crate::hyxewave::misc::Globals;
use crate::hyxewave::misc::Utility::printf_success;
use crate::hyxewave::network::{HyperNode, PacketProcessor};
use crate::hyxewave::network::ExpectanceHandler::*;
use crate::hyxewave::network::Packet::{Packet, PacketQueue, QueueStream};
use crate::hyxewave::network::session::services::ServerDCHandler::dc_handler;
use crate::hyxewave::network::SocketHandler;
use crate::hyxewave::network::SocketHandler::PacketType;

pub struct WaveformListener {
    pub processed_message_packet_map: HyxeObject<HashMap<u64, HashMap<u16, Packet>>>,
    //oid -> pid ~> Packet
    pub processed_5D_packet_map: HyxeObject<HashMap<u64, HashMap<u16, HashMap<u16, HashMap<u16, HashMap<u16, Packet>>>>>>,
    //oid -> z-time -> v-time -> wid -> pid ~> Packet
    pub remote: Remote,
}

impl WaveformListener {
    pub fn new(remote: Remote) -> Self {
        WaveformListener {
            processed_message_packet_map: HyxeObject::new(HashMap::new()),
            processed_5D_packet_map: HyxeObject::new(HashMap::new()),
            remote,
        }
    }
}


