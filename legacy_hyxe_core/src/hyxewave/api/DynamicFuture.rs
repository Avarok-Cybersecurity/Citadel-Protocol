/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::time::Instant;

use futures::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use predicates::prelude::*;
use tokio::prelude::Future;

use hyxe_util::HyxeError;

pub enum FutureSignal<T> where T: Send {
    STOP(String),
    INPUT_TO_SUBROUTINE(T),
    PAUSE_UNTIL(Instant),
    RUN_UNTIL(Instant),
    RUN_WHILE_CONDITION_IS_TRUE(Box<Predicate<bool>>),
    EXECUTE,
    EXECUTE_IF_CONDITION_IS_TRUE(Box<Predicate<bool>>),
    RESUME,
}

/*pub trait DynamicFuture<T, ITEM> where T: Send {
    fn future_subroutine(&mut self) -> Box<Future<Item=ITEM, Error=HyxeError>>;
    fn signal(&mut self, signal: FutureSignal<T>) -> Result<ITEM, HyxeError>;
    fn on_exit(&mut self) -> Result<ITEM, HyxeError>;
    fn on_init(&mut self) -> Result<ITEM, HyxeError>;
}*/

