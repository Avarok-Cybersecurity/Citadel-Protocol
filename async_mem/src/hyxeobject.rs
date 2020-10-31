/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

use std::sync::Arc;

pub use future_parking_lot::{mutex::FutureLockable, rwlock::{FutureReadable, FutureUpgradableReadable, FutureWriteable}};
use serde_derive::{Deserialize, Serialize};

use crate::prelude::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::pin::Pin;
use serde::export::PhantomData;
use std::sync::atomic::AtomicPtr;

#[derive(Serialize, Deserialize, Debug)]
pub struct HyxeObject<'a, Obj> {
    inner: Arc<AtomicPtr<Pin<Box<Obj>>>>,
    _phantom: PhantomData<&'a ()>
}

impl<Obj> HyxeObject<Obj> {
    /// Take control of an object
    pub fn new(obj: Obj) -> Self {
        Self { inner: Arc::new(RwLock::new(obj)) }
    }

    /// Recursively read an object
    pub fn read(&self) -> RwLockReadGuard<Obj> {
        let m = **self.inner.load()
        self.inner.read_recursive()
    }

    /// Read an object strictly, meaning a deadlock is possible if the caller is within a closure which contains a pre-existing read-lock
    pub fn read_strict(&self) -> RwLockReadGuard<Obj> {
        self.inner.read()
    }

    /// Write to the underlying object
    pub fn write(&mut self) -> RwLockWriteGuard<Obj> {
        self.inner.write()
    }
}

impl<Obj> Clone for HyxeObject<Obj> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

unsafe impl<'a, Obj> Send for &'a HyxeObject<Obj> {}

unsafe impl<'a, Obj> Sync for &'a HyxeObject<Obj> {}