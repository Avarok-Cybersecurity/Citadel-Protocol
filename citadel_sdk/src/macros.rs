//! Procedural Macros for Citadel SDK
//!
//! This module provides macro utilities that simplify the implementation of common
//! traits and patterns in the Citadel Protocol SDK. These macros reduce boilerplate
//! code and ensure consistent implementations.
//!
//! # Features
//! - Automatic trait implementation generation
//! - Support for async/await patterns
//! - Integration with protocol communication systems
//!
//! # Example
//! ```rust
//! use citadel_sdk::prelude::*;
//! use citadel_sdk::impl_remote;
//!
//! #[derive(Clone)]
//! struct MyRemote<R: Ratchet> {
//!     inner: NodeRemote<R>,
//! }
//!
//! impl_remote!(MyRemote);
//! ```
//!
//! # Important Notes
//! - Macros are used internally by the SDK
//! - Custom implementations should match the behavior of macro-generated code
//! - Async trait implementations require the async-trait feature
//!
//! # Related Components
//! - [`Remote`]: Core trait for network communication
//! - [`AccountManager`]: User account management
//! - [`NodeRequest`]: Network request handling
//!

#[macro_export]
macro_rules! impl_remote {
    ($item:ident) => {
        #[$crate::async_trait]
        impl<R: $crate::prelude::Ratchet> Remote<R> for $item<R> {
            async fn send_with_custom_ticket(
                &self,
                ticket: Ticket,
                request: NodeRequest,
            ) -> Result<(), NetworkError> {
                self.inner.send_with_custom_ticket(ticket, request).await
            }

            async fn send_callback_subscription(
                &self,
                request: NodeRequest,
            ) -> Result<
                citadel_proto::kernel::kernel_communicator::KernelStreamSubscription<R>,
                NetworkError,
            > {
                self.inner.send_callback_subscription(request).await
            }

            fn account_manager(&self) -> &AccountManager<R, R> {
                self.inner.account_manager()
            }

            fn get_next_ticket(&self) -> Ticket {
                self.inner.get_next_ticket()
            }
        }
    };
}
