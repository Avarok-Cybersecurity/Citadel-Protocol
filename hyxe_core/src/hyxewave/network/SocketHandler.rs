/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

#![feature(await_macro, async_await, futures_api, unboxed_closures, duration_float, checked_duration_since)]

use core::borrow::BorrowMut;
use std::{env, io, thread};
use std::any::Any;
use std::borrow::Borrow;
use std::cell::RefCell;
use std::hash::{Hash, Hasher};
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use bufstream::BufStream;
use bytes::{BufMut, Bytes, BytesMut};
use chrono::prelude::*;
use crossbeam_channel::{Receiver, Sender, unbounded};
use crossbeam_queue::SegQueue;
use futures::Future;
use futures::sink::Sink;
use futures::stream::SplitSink;
use futures::stream::SplitStream;
use futures::stream::Stream;
use futures::sync::mpsc;
use futures::sync::mpsc::UnboundedReceiver;
use futures::task::Task;
use hashbrown::HashMap;
use parking_lot::Mutex;
use rayon::iter::IntoParallelIterator;
use rayon::Scope;
use tokio::codec::{BytesCodec, LinesCodec};
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio::prelude::future::Executor;
use tokio_core::reactor::{Core, Handle, Remote};

use atoi::atoi;
use hyxe_util::HyxeError;
use tokio_kcp::{KcpListener, KcpSessionManager, KcpStream};

use crate::hyxe_util;
use crate::hyxewave::misc::Constants;
use crate::hyxewave::misc::Constants::LOCALHOST;
use crate::hyxewave::misc::Globals;
use crate::hyxewave::misc::Utility::generate_rand_u64;
use crate::hyxewave::network::Packet::{InboundPacket, PacketQueue};

//use tokio::sync::watch::Receiver;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketType {
    WAVE,
    LINEAR,
}


pub struct SocketSink(u32);

impl SocketSink {
    pub fn new() -> Self {
        SocketSink(0)
    }
}

pub fn socket_tube(tube_rx: UnboundedReceiver<String>) -> impl Future<Item=(), Error=HyxeError> {
    futures::lazy(move || {
        tube_rx.from_err::<HyxeError>().for_each(move |signal| {
            println!("[SocketHandler::Tube] Signal {} received", &signal);
            match signal.as_str() {
                "DISCONNECT" => { return HyxeError::throw("DISCONNECT"); } //this should terminate this entire future (connect) for it is selected'
                _ => {}
            }

            Ok(())
        }).map_err(|mut err| err.printf())
    })
}

pub fn listen(port: u16, handle: Handle, stage0_to_stage1_tx: futures::sync::mpsc::UnboundedSender<InboundPacket>, tube_rx: UnboundedReceiver<String>) -> impl Future<Item=(), Error=()> {
    let addr = format!("{}:{}", LOCALHOST, port);
    let addr = addr.parse::<SocketAddr>().unwrap();
    let handle = RefCell::new(handle.clone());

    let sock = KcpListener::bind(&addr, &handle.borrow_mut()).unwrap();

    println!("[SocketListener] Listening on: {}", addr);

    sock.incoming().for_each(move |(mut stream, addr)| {
        //let addr = stream.peer_addr().unwrap();

        if addr.port() == 0 {
            println!("dropping connection {}", addr.to_string());
            return Ok(());
        }

        if Globals::KCP_SESSION_MANAGER.lock().is_none() {
            *Globals::KCP_SESSION_MANAGER.lock() = Some(stream.get_session_manager());
        }

        println!("[SocketHandler] Connection with {} succeeded", addr.to_string());
        let mut framed = tokio_codec::Framed::new(stream, tokio_codec::LinesCodec::new());
        let fan = framed.fanout(SocketSink::new());


        let (mut frame, mut m2) = fan.into_inner();


        let (lines_tx, lines_rx) = frame.split();

        let tx_wave = stage0_tx_wave.clone();
        let tx_linear = stage0_tx_linear.clone();
        let responses = lines_rx.map(move |incoming_message: String| {
            println!("[SocketHandler] incoming_message: {}", incoming_message);
            let packet = base64::decode(&incoming_message.as_bytes().to_vec()).unwrap();
            let msg2 = packet.clone();
            //println!("bytes: {:?}", msg2);
            let src_ip = addr.ip().to_string();
            let src_port = addr.port();
            let buf = packet.clone();
            let utc: DateTime<Utc> = Utc::now();
            println!("[SocketHandler] [{}]: {:?} => {}", addr, msg2, unsafe { String::from_utf8_unchecked(msg2.clone()) });

            //TODO: Ensure the `dest_ip` is later solved. Possibly, abstract-away an InboundPacket, as well as an OutboundPacket?
            stage0_to_stage1_tx.unbounded_send(InboundPacket::new(src_port, src_ip, recv_port, utc.timestamp_millis(), buf)).unwrap();

            buf
        });

        let src_ip = addr.ip().to_string();
        let src_port = addr.port();
        load_outbound_channel(src_ip.clone(), src_port.clone());
        let mut iostream = SocketOutboundStream::new(src_ip, src_port);
        let fwd = iostream.forward(lines_tx).map(|(mut r, e)| {
            ()
        }).map_err(|_| {});

        let writes = responses.fold(m2, move |writer, response| {
            println!("In WRITES");
            let mut resp = format!("You said: {:?}", response);
            writer.send(resp)
        });

        &handle.borrow_mut().spawn(
            writes.then(|_| Ok(()))
        );

        &handle.borrow_mut().spawn(
            fwd
        );

        Ok(())
    }).then(|_| {
        println!("**********HERE**********");
        Ok(())
    }
    ).map_err(|err: std::io::Error| {}).from_err::<HyxeError>().select(socket_tube(tube_rx)).map(|obj| ()).map_err(|(mut err, obj)| ())
}


/// The `tube` is what receives signals from the higher-up manage;r; it's current job is to return an error, thus stopping this future below, when a "RECONNECT" signal is received
pub fn connect(port_local: u16, addr: SocketAddr, handle: Handle, stage0_to_stage1_tx: UnboundedReceiver<InboundPacket>, tube_rx: UnboundedReceiver<String>, mut kcp_session: KcpSessionManager) -> impl Future<Item=(), Error=()> {
    //let kcp = KcpStream::_connect(port_local, &addr, &handle.borrow_mut());
    let kcp = KcpStream::connect(0, &port_local, &addr, &handle, &mut kcp_session);

    if Globals::KCP_SESSION_MANAGER.lock().is_none() {
        *Globals::KCP_SESSION_MANAGER.lock() = Some(kcp_session.clone());
    }

    let handle = RefCell::new(handle.clone());
    futures::lazy(|| kcp).and_then(move |stream| {
        //let addr = stream.peer_addr().unwrap();
        let mut is_recovering = Mutex::new(false);
        let mut kcp_session = kcp_session.clone();

        println!("[SocketHandler] Connection to socket {} success!", addr);
        let mut framed = tokio_codec::Framed::new(stream, tokio_codec::LinesCodec::new());
        let fan = framed.fanout(SocketSink::new());
        let (frame, mut m2) = fan.into_inner();

        let (lines_tx, lines_rx) = frame.split();

        let tx_wave = stage0_tx_wave.clone();
        let tx_linear = stage0_tx_linear.clone();
        let responses = lines_rx.map(move |incoming_message: String| {
            let packet = base64::decode(&incoming_message.as_bytes().to_vec()).unwrap();
            let src_ip = addr.ip().to_string();
            let src_port = addr.port();
            let buf = packet.clone();
            let utc: DateTime<Utc> = Utc::now();
            println!("[SocketHandler] {}: {}", addr, unsafe { String::from_utf8_unchecked(packet.clone()) });

            stage0_to_stage1_tx.unbounded_send(InboundPacket::new(src_port, src_ip, recv_port, utc.timestamp_millis(), buf)).unwrap();

            buf
        });


        let src_ip = addr.ip().to_string();
        let src_port = addr.port();
        load_outbound_channel(src_ip.clone(), src_port.clone());
        let mut iostream = SocketOutboundStream::new(src_ip, src_port);
        let fwd = iostream.forward(lines_tx).map(|(mut r, e)| {
            ()
        });

        let writes = responses.fold(m2, move |writer, response| {
            println!("In WRITES (client)");
            let mut resp = format!("ACK: {}", unsafe { String::from_utf8_unchecked(response) });
            writer.send(resp)
        });

        &handle.borrow_mut().spawn(
            writes.then(|_| Ok(()))
        );

        fwd.then(|res| Ok(()))
    }).map_err(|err: std::io::Error| {}).from_err::<HyxeError>().select(socket_tube(tube_rx)).map(|obj| ()).map_err(|(mut err, obj)| ())
}

impl Sink for SocketSink {
    type SinkItem = String;
    type SinkError = std::io::Error;

    fn start_send(&mut self, item: Self::SinkItem) -> Result<AsyncSink<Self::SinkItem>, Self::SinkError> {
        //println!("In start send");
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Result<Async<()>, Self::SinkError> {
        //println!("In poll complete");
        Ok(Async::Ready(()))
    }

    fn close(&mut self) -> Result<Async<()>, Self::SinkError> {
        //println!("In close");
        Ok(Async::Ready(()))
    }
}

pub struct SocketOutboundStream {
    ip: String,
    port: u16,
    receiver: Arc<Mutex<SegQueue<String>>>,
    has_loaded: bool,
}

impl SocketOutboundStream {
    pub fn new(ip: String, port: u16) -> Self {
        SocketOutboundStream { ip: ip.clone(), port: port.clone(), receiver: acquire_sender(&ip, &port).unwrap(), has_loaded: false }
    }
}

impl Stream for SocketOutboundStream {
    type Item = String;
    type Error = std::io::Error;
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        //println!("SocketOutboundStream being polled {}", generate_rand_u64());
        if !self.has_loaded {
            let key = format!("{}:{}", self.ip, self.port);
            Globals::SOCKET_TASKS_INPUT.lock().insert(key, Arc::new(Mutex::new(task::current())));
        }
        if !self.receiver.lock().is_empty() {
            let str_recv = self.receiver.lock().pop().unwrap();
            println!("[STREAM->Outbound] {}", str_recv);
            return Ok(Async::Ready(Some(str_recv)));
        } else {
            return Ok(Async::NotReady);
        }
    }
}

pub fn acquire_sender(ip_to: &String, port: &u16) -> Option<Arc<Mutex<SegQueue<String>>>> {
    let hashmap = Globals::SOCKET_WRITERS.lock();
    //println!("map len: {}", hashmap.len());
    if let Some(inner_map) = hashmap.get(ip_to) {
        //println!("inner_map: {}", inner_map.lock().len());
        let inner_map = inner_map.lock();
        if let Some(sender) = inner_map.get(port) {
            return Some(Arc::clone(sender));
        }
    }
    None
}

pub fn send_packet_async<F>(packet: ProcessedInboundPacket, remote: &Remote, expect_response: bool, expectancies: Option<&'static [&str]>, fx: Option<F>) -> impl Future<Item=Option<ProcessedInboundPacket>, Error=String>
    where F: Fn(Option<ProcessedInboundPacket>, Remote) -> std::result::Result<&'static str, std::io::Error> {
    futures::lazy(move || {
        println!("Sending a packet (async)");

        let sender = acquire_sender(packet.get_dest_ip(), packet.get_dest_port());
        if let Some(sender) = sender {
            let key = format!("{}:{}", packet.get_dest_ip().clone().to_owned(), packet.get_dest_port().clone().to_owned());
            sender.lock().push(base64::encode(&packet.get_message()));

            Globals::SOCKET_TASKS_INPUT.lock().get(&key).unwrap().lock().notify();

            if let Some(expectancies) = expectancies {
                if let Some(fx) = fx {
                    println!("Injecting expectancy parameters into ExpectanceQueue");
                    //do-inject here
                }
            }
            return Ok(None);
        }
        eprintln!("[SocketHandler] Invalid configuration for packet");
        Ok(None)
    })
}

fn load_outbound_channel(ip_dest: String, port: u16) {
    println!("loading tx-outbound channel: {}:{}", ip_dest, port);
    let mut hashmap = Globals::SOCKET_WRITERS.lock();
    if !hashmap.contains_key(&ip_dest.clone()) {
        hashmap.insert(ip_dest.clone(), Mutex::new(HashMap::new()));
    }
    hashmap.get(&ip_dest).unwrap().lock().insert(port, Arc::new(Mutex::new(SegQueue::new())));
}

pub fn read_stdin(remote: Remote) {
    let mut stdin = io::stdin();
    println!("Reading stdin (debug)");
    loop {
        let mut buf = vec![0; 1024];
        let n = match stdin.read(&mut buf) {
            Err(_) | Ok(0) => break,
            Ok(n) => n,
        };
        buf.truncate(n);

        let s = String::from_utf8(buf).unwrap();
        let parts: Vec<&str> = s.split(",").collect();
        if parts.len() != 3 {
            println!("invalid input: {}", s);
            continue;
        }

        let s = s.clone();
        let ip = parts[0].to_string();
        if let Some(port) = atoi::<u16>(parts[1].as_bytes()) {
            let data = parts[2].to_string().replace("\n", "");
            println!("Parsed IP[{}] and Port[{}] and Data[{}]", ip, port, data);
            let mut data_bytes = data.clone().into_bytes();


            println!("Sending input: {}", s);

            let packet = Packet::new("::".to_string(), 0, ip, port, data_bytes, PacketType::LINEAR);
            remote.spawn(|h| {
                send_packet_async(packet, h.remote(), false, None, Some(|packet: Option<ProcessedInboundPacket>, remote|
                    {
                        let mut packet = packet.unwrap();
                        Err(Error::new(ErrorKind::Other, "error!"))
                    })).then(|packet| Ok(()))
            });
        } else {
            eprintln!("Invalid port specified");
        }
    }
}
