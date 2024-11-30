//! Network Synchronization Primitives Module
//!
//! This module provides distributed synchronization primitives that work across network boundaries.
//! These primitives enable synchronized access to shared state between different network endpoints.
//!
//! # Features
//! - Network-aware mutex for exclusive access across endpoints
//! - Network-aware read-write lock for shared/exclusive access across endpoints
//! - Trait definitions for network-compatible objects
//!
//! # Important Notes
//! - All primitives require objects to implement the `NetObject` trait
//! - Objects must be serializable, deserializable, and thread-safe
//! - Network operations may fail due to connection issues, so error handling is essential
//!
//! # Related Components
//! - [`net_mutex`] - Distributed mutual exclusion
//! - [`net_rwlock`] - Distributed read-write locking

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

pub mod net_mutex;
pub mod net_rwlock;

pub trait NetObject: Debug + Serialize + DeserializeOwned + Send + Sync + Clone + 'static {}
impl<T: Debug + Serialize + DeserializeOwned + Send + Sync + Clone + 'static> NetObject for T {}
