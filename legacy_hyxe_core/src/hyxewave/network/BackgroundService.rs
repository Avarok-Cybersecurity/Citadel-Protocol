/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::{Executor, FutureResult};
use futures::stream::Stream;
use futures::sync::mpsc::{Receiver, Sender, unbounded};
use mut_static::MutStatic;
use parking_lot::Mutex;
use tokio::prelude::{Future, future};
use tokio::timer::{Delay, Interval};
use tokio_core::reactor::Remote;

use hyxe_util::HyxeError;
use QuantumRandom::EntropyBank;

use crate::hyxewave::misc::{Constants, Globals};
use crate::hyxewave::network::{BridgeHandler::BridgeHandler, HyperNode};

pub fn background_service(remote: Remote, bridge: Arc<Mutex<BridgeHandler>>) -> impl Future<Item=(), Error=HyxeError> {
    Globals::ENTROPY_BANK_IS_UPDATING.set(false);

    Interval::new(Instant::now(), Duration::from_millis(Constants::BACKGROUND_CHECK_DELAY as u64)).from_err().for_each(move |instant| {
        if !Globals::system_engaged() {
            return HyxeError::throw("[BackgroundService] System set to shut down");
        }

        if !EntropyBank::default_entropy_bank_loaded_to_memory_and_is_valid() && !*Globals::ENTROPY_BANK_IS_UPDATING.read().unwrap() {
            Globals::ENTROPY_BANK_IS_UPDATING.set(true);
            let remote = remote.clone();
            remote.clone().execute(EntropyBank::load(None, remote.clone()).and_then(move |bank| {
                if bank.unwrap().lock().did_expire().unwrap() {
                    println!("[BackgroundService] Local Quantum Entropy Bank Expired! Rescrambling...");
                    remote.clone().execute(EntropyBank::new_async(remote.clone(), QuantumRandom::random::ENTROPY_BANK_SIZE).then(move |res| {
                        if let Ok(bank_new) = res {
                            bank_new.lock().save(None);
                            Globals::ENTROPY_BANK_IS_UPDATING.set(false);
                            Ok(())
                        } else {
                            Err(res.unwrap_err())
                        }
                    }).map_err(|mut err| {}));
                }
                Ok(())
            }).map_err(|err| {})).unwrap();
        }
        Ok(())
    })
}