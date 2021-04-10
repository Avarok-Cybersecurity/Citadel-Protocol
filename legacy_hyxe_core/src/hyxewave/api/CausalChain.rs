/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::any::Any;
use std::sync::Arc;

use parking_lot::Mutex;

use hyxe_util::HyxeError;

pub enum Operation {
    AND,
    OR,
    ADD,
    SUB,
    MULT,
    DIV,
    MAP,
    THEN,
    AND_THEN,
}

pub trait Atom<T> where T: Send + Sync + Any {
    type Output;


    fn subroutine(self) -> Self::Output;
}

pub struct Automorph;

impl<T> Atom<T> for Automorph where T: Send + Sync + Any {
    type Output = String;

    fn subroutine(self) -> Self::Output {
        String::new()
    }
}

pub struct CausalChain {
    atoms: Vec<Automorph>
}


pub struct ExecutableAction<F, Z>
    where
        F: FnMut() -> Z + Send + Sync,
{
    action: Arc<Mutex<Box<F>>>,
}

impl<F, Z> ExecutableAction<F, Z>
    where
        F: FnMut() -> Z + Send + Sync,
        Z: Send + Sync,
{
    pub fn create(closure: F) -> Self {
        Self {
            action: Arc::new(Mutex::new(Box::new(closure))),
        }
    }

    pub fn call(&mut self) -> Z {
        let mut f = self.action.lock();
        (&mut *f)()
    }
}



