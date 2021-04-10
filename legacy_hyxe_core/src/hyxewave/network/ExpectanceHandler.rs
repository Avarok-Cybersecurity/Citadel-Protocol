/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::any::Any;
use std::cell::UnsafeCell;
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_queue::SegQueue;
use futures::future::Executor;
use futures::prelude::*;
use futures::task::Task;
use hashbrown::HashMap;
use parking_lot::Mutex;
use rand::prelude::*;
use tokio::prelude::future;
use tokio::timer::{Delay, Interval};
use tokio_core::reactor::{Core, Handle, Remote, Timeout};

use hyxe_util::HyxeError;

use crate::HyxeObject;
use crate::hyxewave::misc::Globals;
use crate::hyxewave::network::Packet::{ProcessedInboundPacket, QueueStream};

pub struct ExecutableClosure {
    action: Arc<Mutex<Box<Fn(Option<ProcessedInboundPacket>, Remote) -> Result<String, HyxeError> + Send>>>
}

impl ExecutableClosure {
    pub fn new<F: 'static>(fx: F) -> Self where F: Fn(Option<ProcessedInboundPacket>, Remote) -> Result<String, HyxeError> + Send {
        ExecutableClosure { action: Arc::new(Mutex::new(Box::new(fx))) }
    }

    pub fn execute(&self, packet: Option<ProcessedInboundPacket>, remote: Remote) -> Result<String, HyxeError> {
        self.action.lock().call((packet, remote))
    }
}

pub struct Expectancy {
    pub oid_eid: u64,
    remote: Remote,
    on_packet_received: ExecutableClosure,
    timeout: Duration,
    pub is_recurrent: bool,
    pub can_run: bool,
}

impl Expectancy {
    /// The `remote` must belong to a thread than the calling function!
    pub fn attach_oneshot(oid_eid: u64, remote: Remote, timeout: usize, on_packet_received: ExecutableClosure) {
        let timeout_duration = Duration::from_millis(timeout as u64);

        let mut exp = Expectancy { oid_eid, is_recurrent: false, remote: remote.clone(), on_packet_received, timeout: timeout_duration, can_run: true };
        let exp = Arc::new(Mutex::new(exp));

        /// Attach to global list
        Globals::EXP_QUEUES.lock().insert(oid_eid, exp);

        let exp_timeout = Arc::clone(&exp);
        let timeout_instant = Instant::now() + timeout_duration;


        let timeout = Delay::new(timeout_instant).and_then(move |_| {
            println!("[ExpectanceHandler] Checking to see if eid {} completed [timeout={}ms]", &oid_eid, &timeout);
            let unfinished_exp_opt = Globals::EXP_QUEUES.lock().remove(&oid_eid);
            if unfinished_exp_opt.is_some() {
                let unfinished_exp = unfinished_exp_opt.unwrap();
                eprintln!("[ExpectancyHandler] Timeout reached for expectancy {}", &oid_eid);
                unfinished_exp.lock().on_timeout();
            } else {
                println!("[ExpectancyHandler] Expectancy {} already fulfilled!", &oid_eid);
            }
            Ok(())
        });

        remote.execute(timeout.map_err(move |err| {
            eprintln!("[ExpectancyHandler] Expectancy-future encountered an issue: {:#?}", err);
        })).unwrap();
    }

    pub fn attach_recurrent(oid_eid: u64, remote: Remote, stall_check_rate: usize, on_packet_received: ExecutableClosure) {
        /// If the expectancy is recurrent, then a periodic timer will check on it to see if it still needs to be ran.
           /// This is useful, for example, if there is an expectancy for an object that requires a certain number of packets,
           /// and supposing that certain number isn't reached in a reasonable time (determined by the inner closure), the
           /// timer will stop if signalled to.

        let stall_duration = Duration::from_millis(stall_check_rate as u64);

        let mut exp = Expectancy { oid_eid, is_recurrent: true, remote: remote.clone(), on_packet_received, timeout: stall_duration, can_run: true };
        let exp = Arc::new(Mutex::new(exp));

        /// Attach to global list
        Globals::EXP_QUEUES.lock().insert(oid_eid, exp);

        let exp_timeout = Arc::clone(&exp);
        let timeout_instant = Instant::now() + stall_duration;

        let recurrent_checker = Interval::new(Instant::now(), stall_duration).take_while(move |instant| {
            let mut result: Option<FutureResult<bool, tokio::timer::Error>> = None;
            let exp_inner = Arc::clone(&exp);
            let exp_inner = exp_inner.lock();

            match *exp_inner.can_run {
                true => result = {
                    println!("[Expectancy] [Recurrent] Will continue to check oid_eid {}", &oid_eid);
                    Some(future::ok(true))
                },
                _ => result = {
                    eprintln!("[Expectancy] [Recurrent] Will shutdown listener for oid_eid {}", &oid_eid);
                    let converged_exp = Globals::EXP_QUEUES.lock().remove(&oid_eid).unwrap();
                    converged_exp.lock().on_timeout();
                    Some(future::err(tokio::timer::Error::shutdown()))
                }
            }

            result.unwrap()
        }).for_each(move |instant| {
            println!("[Expectancy] [Recurrent] Checking closure of oid_eid {} in-case of hangup...", &oid_eid);
            let exp_inner = Arc::clone(&exp);

            //Below, we want to try locking the mutex, as it may be concurrently being driven
            if let Some(exp_inner) = exp_inner.try_lock() {
                exp_inner.execute(None, remote.clone());
            }
            Ok(())
        });

        remote.execute(recurrent_checker.map_err(move |err| {
            eprintln!("[ExpectancyHandler] Expectancy-future encountered an issue: {:#?}", err);
        })).unwrap();
    }

    /// This closure will be called reguardless if the expected packet returned or not.
    /// Lambda parameter `packet` is None if the timeout is reached (for oneshots). For recurrents, `packet` is None if a status-check is requested.
    /// DO NOT BLOCK HERE! provide futures as needed using the parallel remote given if needing to perform a computationally expensive subroutine
    /// IMPORTANT: THE REMOTE PASSED INTO THE LAMBDA PARAMETER MUST BELONG TO A DIFFERENT
    /// ASYNC-CORE THAN THE REMOTE DRIVING OTHER STAGES. THE REMOTE PASSED INTO THIS FUNCTION
    /// MUST BE OKAY WITH COMPUTATIONALLY-INTENSIVE PROCESSES
    pub fn execute(&self, packet: Option<ProcessedInboundPacket>, remote: Remote) -> Result<String, HyxeError> {
        self.on_packet_received.execute(packet, remote)
    }

    pub fn on_timeout(&self) {
        self.on_packet_received.execute(None, self.remote.clone());
    }
}

pub struct ExpectancyStream {
    expectancy_map: Arc<Mutex<HashMap<u64, Arc<Mutex<Expectancy>>>>>,
    packets: Arc<Mutex<HashMap<u64, Packet>>>,
    loaded_task: bool,
}

impl ExpectancyStream {
    pub fn new() -> Self {
        ExpectancyStream { expectancy_map: Arc::new(Mutex::new(HashMap::new())), packets: Arc::new(Mutex::new(HashMap::new())), loaded_task: false }
    }

    pub fn inject_packet(&mut self, mut packet: ProcessedInboundPacket) {
        self.packets.lock().insert(packet.get_eid().unwrap(), packet);
    }
}

//This streams returns an object of type Expectancy once it finds a match
impl Stream for ExpectancyStream {
    type Item = (Packet, Arc<Mutex<Expectancy>>);
    type Error = std::io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if !self.loaded_task {
            println!("[ExpectancyStream] NOTE: Your configuration allows up to 1 ExpectancyHandler");
            Globals::EXP_GLOBAL_TASKS.lock().insert(0 as u8, futures::task::current());
        }

        for (id, expectancy) in self.expectancy_map.lock().iter() {
            if let Some(matched_packet) = self.packets.lock().remove(id) {
                println!("Expectance-value {} matched!", id);
                return Ok(Async::Ready(Some((matched_packet, Arc::clone(expectancy)))));
            }
        }
        Ok(Async::NotReady)
    }
}

unsafe impl Send for ExpectancyStream {}

unsafe impl Send for ExecutableClosure {}

unsafe impl Send for Expectancy {}