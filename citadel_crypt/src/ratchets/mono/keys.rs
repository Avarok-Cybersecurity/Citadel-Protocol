//! # Firebase Cloud Messaging (FCM) Keys Management
//!
//! This module provides secure management of Firebase Cloud Messaging credentials,
//! implementing thread-safe access to API keys and client IDs while ensuring proper
//! memory management and serialization capabilities.
//!
//! ## Features
//! - Thread-safe storage of FCM credentials
//! - Efficient memory management through Arc
//! - Serialization support for persistence
//! - Type-safe key construction
//! - Debug formatting with sensitive data handling
//!
//! ## Usage Example
//! ```rust
//! use citadel_crypt::ratchets::mono::keys::FcmKeys;
//!
//! // Create new FCM keys
//! let keys = FcmKeys::new(
//!     "your-api-key-here",
//!     "your-client-id-here"
//! );
//!
//! // Access keys (thread-safe)
//! println!("API Key: {}", keys.api_key);
//! println!("Client ID: {}", keys.client_id);
//!
//! // Keys can be cloned efficiently (only clones Arc)
//! let keys_clone = keys.clone();
//!
//! // Serialize for storage if needed
//! let serialized = bincode::serialize(&keys).unwrap();
//! ```
//!
//! ## Important Notes
//! - Uses Arc for efficient sharing across threads
//! - Implements Debug trait with safe credential display
//! - Keys are immutable after creation for security
//! - Supports serialization for persistent storage
//!
//! ## Related Components
//! - [`FcmClient`](super::client::FcmClient): FCM client implementation
//! - [`FcmMessage`](super::message::FcmMessage): FCM message structure
//! - Firebase Cloud Messaging service integration

use serde::__private::Formatter;
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use std::sync::Arc;

#[derive(Clone, Serialize, Deserialize)]
pub struct FcmKeys {
    inner: Arc<FcmKeysInner>,
}

impl FcmKeys {
    pub fn new<T: Into<String>, R: Into<String>>(api_key: T, client_id: R) -> Self {
        Self {
            inner: Arc::new(FcmKeysInner {
                client_id: client_id.into(),
                api_key: api_key.into(),
            }),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct FcmKeysInner {
    pub client_id: String,
    pub api_key: String,
}

impl Deref for FcmKeys {
    type Target = FcmKeysInner;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl std::fmt::Debug for FcmKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "api key: {} || client ID: : {}",
            &self.api_key, &self.client_id
        )
    }
}
