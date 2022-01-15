/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use futures::future::FutureResult;

use hyxe_util::HyxeError;

pub mod SAAQ;
pub mod ServerDCHandler;
pub mod ConnectionWorker;

pub trait Service {
    fn get_period_ms(&self) -> usize;
    fn can_run(&mut self) -> Option<FutureResult<bool, tokio::timer::Error>>;
    fn on_call_subroutine(&mut self) -> Result<bool, HyxeError>;
}