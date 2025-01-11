//! # Citadel Protocol Core Implementation
//!
//! The `citadel_proto` crate provides the core implementation of the Citadel Protocol, a secure and
//! efficient networking protocol designed for peer-to-peer communication with post-quantum cryptographic
//! security guarantees.
//!
//! ## Key Features
//!
//! - **Post-Quantum Security**: Built with resistance against both classical and quantum attacks
//! - **Peer-to-Peer Communication**: Direct peer connections with NAT traversal capabilities
//! - **Session Management**: Robust session handling with automatic reconnection and state management
//! - **Secure File Transfer**: Built-in support for secure file transfers with configurable security levels
//! - **Group Communication**: Support for secure group messaging and broadcasts
//! - **UDP/TCP Support**: Flexible transport layer with support for both UDP and TCP connections
//! - **Zero-Copy Design**: Optimized for performance with minimal memory overhead
//! - **Async/Await Support**: Built on modern Rust async primitives
//! - **Cross-Platform**: Works on all major platforms including mobile
//!
//! ## Architecture
//!
//! The protocol is built around several key components:
//!
//! - **Kernel Layer**: Core event loop and task scheduling via [`kernel`] module
//! - **Protocol Layer**: Protocol implementation and packet handling in [`proto`] module
//! - **Session Management**: Connection lifecycle via [`CitadelSession`]
//! - **Security Layer**: Cryptographic operations and security settings
//! - **Network Layer**: Transport abstraction and connection management
//!
//! ## Module Organization
//!
//! - [`kernel`]: Core event loop and task scheduling
//! - [`proto`]: Protocol implementation and packet handling
//! - [`prelude`]: Common imports for working with the crate
//! - [`error`]: Error types and handling
//!
//! ## Security Considerations
//!
//! - All sensitive data is automatically zeroed when dropped
//! - The crate forbids unsafe code by default
//! - Implements defense-in-depth with multiple security layers
//! - Uses post-quantum cryptographic primitives
//! - Provides configurable security levels
//!
//! ## Performance
//!
//! The crate is designed for high performance with:
//! - Zero-copy packet handling where possible
//! - Efficient memory management
//! - Optimized async/await implementations
//! - Minimal allocations in hot paths
//!
//! ## Examples
//!
//! See the `examples/` directory in the repository for complete usage examples.
//! For quick start guides and tutorials, visit the official documentation.
//!
//! ## Feature Flags
//!
//! - `multi-threaded`: Enables multi-threaded support
//!
//! ## Version Compatibility
//!
//! This crate maintains semantic versioning and documents breaking changes
//! in the changelog. It is recommended to specify exact version requirements
//! in your `Cargo.toml`.
#![doc(html_no_source)]
#![forbid(unsafe_code)]
#![deny(
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    variant_size_differences,
    unused_features,
    warnings,
    dead_code
)]
#![allow(rustdoc::broken_intra_doc_links)]

use crate::error::NetworkError;
use crate::proto::session::UserMessage;
use citadel_crypt::messaging::{
    RatchetManagerMessengerLayer, RatchetManagerMessengerLayerRx, RatchetManagerMessengerLayerTx,
};
use citadel_crypt::ratchets::ratchet_manager::DefaultRatchetManager;

#[cfg(not(feature = "multi-threaded"))]
pub const fn build_tag() -> &'static str {
    "Single-Threaded"
}

#[cfg(feature = "multi-threaded")]
pub const fn build_tag() -> &'static str {
    "Multi-Threaded"
}

#[cfg(not(feature = "multi-threaded"))]
#[macro_use]
pub mod macros {
    use either::Either;
    use std::future::Future;

    use crate::proto::session::CitadelSessionInner;

    pub type OwnedReadGuard<'a, T> = std::cell::Ref<'a, T>;
    pub type OwnedWriteGuard<'a, T> = std::cell::RefMut<'a, T>;

    pub type EitherOwnedGuard<'a, T> = Either<OwnedReadGuard<'a, T>, OwnedWriteGuard<'a, T>>;

    pub trait ContextRequirements: 'static {}
    impl<T: 'static> ContextRequirements for T {}

    pub trait LocalContextRequirements<'a>: 'a {}
    impl<'a, T: 'a> LocalContextRequirements<'a> for T {}

    pub trait SyncContextRequirements: 'static {}
    impl<T: 'static> SyncContextRequirements for T {}

    pub trait FutureRequirements: ContextRequirements + Future {}
    impl<T: ContextRequirements + Future> FutureRequirements for T {}

    pub type WeakBorrowType<T> = std::rc::Weak<std::cell::RefCell<T>>;
    pub type SessionBorrow<'a, R> = std::cell::RefMut<'a, CitadelSessionInner<R>>;

    pub struct WeakBorrow<T> {
        pub inner: std::rc::Weak<std::cell::RefCell<T>>,
    }

    impl<T> Clone for WeakBorrow<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }

    macro_rules! inner {
        ($item:expr) => {
            $item.inner.borrow()
        };
    }

    macro_rules! inner_mut {
        ($item:expr) => {
            $item.inner.borrow_mut()
        };
    }

    macro_rules! inner_state {
    ($item:expr) => {
        //$item.inner.try_read_for(std::time::Duration::from_millis(10)).expect("PANIC ON READ (TIMEOUT)")
        $item.inner.borrow()
    };
}

    macro_rules! inner_mut_state {
    ($item:expr) => {
        //$item.inner.try_write_for(std::time::Duration::from_millis(10)).expect("PANIC ON WRITE (TIMEOUT)")
        $item.inner.borrow_mut()
    };
}

    macro_rules! define_outer_struct_wrapper {
    // Version with generic parameters
    ($struct_name:ident, $inner:ident, <$($generic:ident $(: $bound:path)?),*>, <$($use_generic:ident),*>) => {
        #[derive(Clone)]
        pub struct $struct_name<$($generic $(: $bound)?),*> {
            pub inner: std::rc::Rc<std::cell::RefCell<$inner<$($use_generic),*>>>,
        }

        impl<$($generic $(: $bound)?),*> $struct_name<$($use_generic),*> {
            #[allow(dead_code)]
            pub fn as_weak(&self) -> crate::macros::WeakBorrow<$inner<$($use_generic),*>> {
                crate::macros::WeakBorrow {
                    inner: std::rc::Rc::downgrade(&self.inner),
                }
            }

            #[allow(dead_code)]
            pub fn upgrade_weak(
                this: &crate::macros::WeakBorrow<$inner<$($use_generic),*>>,
            ) -> Option<$struct_name<$($use_generic),*>> {
                this.inner.upgrade().map(|inner| Self { inner })
            }

            #[allow(dead_code)]
            pub fn strong_count(&self) -> usize {
                std::rc::Rc::strong_count(&self.inner)
            }

            #[allow(dead_code)]
            pub fn weak_count(&self) -> usize {
                std::rc::Rc::weak_count(&self.inner)
            }
        }

        impl<$($generic $(: $bound)?),*> From<$inner<$($use_generic),*>> for $struct_name<$($use_generic),*> {
            fn from(inner: $inner<$($use_generic),*>) -> Self {
                Self {
                    inner: create_inner!(inner),
                }
            }
        }
    };

    // Simple version without generic parameters
    ($struct_name:ident, $inner:ty) => {
        #[derive(Clone)]
        pub struct $struct_name {
            pub inner: std::rc::Rc<std::cell::RefCell<$inner>>,
        }

        impl $struct_name {
            #[allow(dead_code)]
            pub fn as_weak(&self) -> crate::macros::WeakBorrow<$inner> {
                crate::macros::WeakBorrow {
                    inner: std::rc::Rc::downgrade(&self.inner),
                }
            }

            #[allow(dead_code)]
            pub fn upgrade_weak(
                this: &crate::macros::WeakBorrow<$inner>,
            ) -> Option<$struct_name> {
                this.inner.upgrade().map(|inner| Self { inner })
            }

            #[allow(dead_code)]
            pub fn strong_count(&self) -> usize {
                std::rc::Rc::strong_count(&self.inner)
            }

            #[allow(dead_code)]
            pub fn weak_count(&self) -> usize {
                std::rc::Rc::weak_count(&self.inner)
            }
        }

        impl From<$inner> for $struct_name {
            fn from(inner: $inner) -> Self {
                Self {
                    inner: create_inner!(inner),
                }
            }
        }
    };
}

    macro_rules! create_inner {
        ($item:expr) => {
            std::rc::Rc::new(std::cell::RefCell::new($item))
        };
    }

    macro_rules! spawn {
        ($future:expr) => {
            crate::proto::misc::panic_future::ExplicitPanicFuture::new(
                citadel_io::tokio::task::spawn_local($future),
            )
        };
    }

    macro_rules! spawn_handle {
        ($future:expr) => {
            crate::proto::misc::panic_future::ExplicitPanicFuture::new(
                citadel_io::tokio::task::spawn_local($future),
            )
        };
    }

    macro_rules! to_concurrent_processor {
        ($future:expr) => {
            return $future.await
        };
    }

    macro_rules! return_if_none {
        ($opt:expr) => {
            return_if_none!($opt, stringify!($opt))
        };

        ($opt:expr, $err:expr) => {
            match $opt {
                Some(val) => val,
                _ => {
                    log::warn!(target: "citadel", "[X-03] NoneError: {}", $err);
                    return Ok(PrimaryProcessorResult::Void);
                }
            }
        }
    }
}

#[cfg(feature = "multi-threaded")]
#[macro_use]
pub mod macros {
    use either::Either;
    use std::future::Future;

    use crate::proto::session::CitadelSessionInner;

    pub type OwnedReadGuard<'a, T> = citadel_io::RwLockReadGuard<'a, T>;
    pub type OwnedWriteGuard<'a, T> = citadel_io::RwLockWriteGuard<'a, T>;

    pub type EitherOwnedGuard<'a, T> = Either<OwnedReadGuard<'a, T>, OwnedWriteGuard<'a, T>>;

    pub trait ContextRequirements: Send + 'static {}
    impl<T: Send + 'static> ContextRequirements for T {}

    pub trait LocalContextRequirements<'a>: Send + 'a {}
    impl<'a, T: Send + 'a> LocalContextRequirements<'a> for T {}

    pub trait SyncContextRequirements: Send + Sync + 'static {}
    impl<T: Send + Sync + 'static> SyncContextRequirements for T {}

    pub trait FutureRequirements: ContextRequirements + Future {}
    impl<T: ContextRequirements + Future> FutureRequirements for T {}

    pub type WeakBorrowType<T> = std::sync::Weak<citadel_io::RwLock<T>>;
    pub type SessionBorrow<'a, R> = citadel_io::RwLockWriteGuard<'a, CitadelSessionInner<R>>;

    pub struct WeakBorrow<T> {
        pub inner: std::sync::Weak<citadel_io::RwLock<T>>,
    }

    impl<T> Clone for WeakBorrow<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }

    macro_rules! inner {
    ($item:expr) => {
        //$item.inner.try_read_for(std::time::Duration::from_millis(10)).expect("PANIC ON READ (TIMEOUT)")
        $item.inner.read()
    };
}

    macro_rules! inner_mut {
    ($item:expr) => {
        //$item.inner.try_write_for(std::time::Duration::from_millis(10)).expect("PANIC ON WRITE (TIMEOUT)")
        $item.inner.write()
    };
}

    macro_rules! inner_state {
    ($item:expr) => {
        //$item.inner.try_read_for(std::time::Duration::from_millis(10)).expect("PANIC ON READ (TIMEOUT)")
        $item.inner.read()
    };
}

    macro_rules! inner_mut_state {
    ($item:expr) => {
        //$item.inner.try_write_for(std::time::Duration::from_millis(10)).expect("PANIC ON WRITE (TIMEOUT)")
        $item.inner.write()
    };
}

    macro_rules! define_outer_struct_wrapper {
    // Version with generic parameters
    ($struct_name:ident, $inner:ident, <$($generic:ident $(: $bound:path)?),*>, <$($use_generic:ident),*>) => {
        #[derive(Clone)]
        pub struct $struct_name<$($generic $(: $bound)?),*> {
            pub inner: std::sync::Arc<citadel_io::RwLock<$inner<$($use_generic),*>>>,
        }

        impl<$($generic $(: $bound)?),*> $struct_name<$($use_generic),*> {
            #[allow(dead_code)]
            pub fn as_weak(&self) -> crate::macros::WeakBorrow<$inner<$($use_generic),*>> {
                crate::macros::WeakBorrow {
                    inner: std::sync::Arc::downgrade(&self.inner),
                }
            }

            #[allow(dead_code)]
            pub fn upgrade_weak(
                this: &crate::macros::WeakBorrow<$inner<$($use_generic),*>>,
            ) -> Option<$struct_name<$($use_generic),*>> {
                this.inner.upgrade().map(|inner| Self { inner })
            }

            #[allow(dead_code)]
            pub fn strong_count(&self) -> usize {
                std::sync::Arc::strong_count(&self.inner)
            }

            #[allow(dead_code)]
            pub fn weak_count(&self) -> usize {
                std::sync::Arc::weak_count(&self.inner)
            }
        }

        impl<$($generic $(: $bound)?),*> From<$inner<$($use_generic),*>> for $struct_name<$($use_generic),*> {
            fn from(inner: $inner<$($use_generic),*>) -> Self {
                Self {
                    inner: create_inner!(inner),
                }
            }
        }
    };

    // Simple version without generic parameters
    ($struct_name:ident, $inner:ty) => {
        #[derive(Clone)]
        pub struct $struct_name {
            pub inner: std::sync::Arc<citadel_io::RwLock<$inner>>,
        }

        impl $struct_name {
            #[allow(dead_code)]
            pub fn as_weak(&self) -> crate::macros::WeakBorrow<$inner> {
                crate::macros::WeakBorrow {
                    inner: std::sync::Arc::downgrade(&self.inner),
                }
            }

            #[allow(dead_code)]
            pub fn upgrade_weak(
                this: &crate::macros::WeakBorrow<$inner>,
            ) -> Option<$struct_name> {
                this.inner.upgrade().map(|inner| Self { inner })
            }

            #[allow(dead_code)]
            pub fn strong_count(&self) -> usize {
                std::sync::Arc::strong_count(&self.inner)
            }

            #[allow(dead_code)]
            pub fn weak_count(&self) -> usize {
                std::sync::Arc::weak_count(&self.inner)
            }
        }

        impl From<$inner> for $struct_name {
            fn from(inner: $inner) -> Self {
                Self {
                    inner: create_inner!(inner),
                }
            }
        }
    };
}

    macro_rules! create_inner {
        ($item:expr) => {
            std::sync::Arc::new(citadel_io::RwLock::new($item))
        };
    }

    #[allow(unused_results)]
    macro_rules! spawn {
    ($future:expr) => {
        if citadel_io::tokio::runtime::Handle::try_current().is_ok() {
            std::mem::drop(crate::proto::misc::panic_future::ExplicitPanicFuture::new(citadel_io::tokio::task::spawn($future)));
        } else {
            log::warn!(target: "citadel", "Unable to spawn future: {:?}", stringify!($future));
        }
    };
}

    macro_rules! spawn_handle {
        ($future:expr) => {
            crate::proto::misc::panic_future::ExplicitPanicFuture::new(
                citadel_io::tokio::task::spawn($future),
            )
        };
    }

    macro_rules! to_concurrent_processor {
        ($future:expr) => {
            return $future.await
        };
    }

    macro_rules! return_if_none {
        ($opt:expr) => {
            return_if_none!($opt, "NoneError Default")
        };

        ($opt:expr, $err:expr) => {
            match $opt {
                Some(val) => val,
                _ => {
                    log::warn!(target: "citadel", "NoneError in file {}:{}: {}", file!(), line!(), $err);
                    return Ok(PrimaryProcessorResult::Void);
                }
            }
        }
    }
}

#[cfg(not(target_family = "wasm"))]
pub mod re_imports {
    pub use async_trait::*;
    pub use bytes::BufMut;
    pub use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
    pub use futures::future::try_join3;

    pub use citadel_io::tokio_stream::wrappers::UnboundedReceiverStream;
    pub use citadel_io::tokio_util::io::{SinkWriter, StreamReader};
    pub use citadel_pqcrypto::build_tag;
    pub use citadel_wire::exports::rustls_pemfile;
    pub use citadel_wire::exports::ClientConfig as RustlsClientConfig;
    pub use citadel_wire::hypernode_type::NodeType;
    pub use citadel_wire::quic::insecure;
    pub use citadel_wire::tls::{
        cert_vec_to_secure_client_config, create_rustls_client_config, load_native_certs_async,
    };
}

pub mod prelude {
    pub use citadel_crypt::argon::argon_container::ArgonDefaultServerSettings;
    #[cfg(not(coverage))]
    pub use citadel_crypt::argon::autotuner::calculate_optimal_argon_params;
    pub use citadel_crypt::ratchets::mono::keys::FcmKeys;
    pub use citadel_crypt::ratchets::mono::MonoRatchet;
    pub use citadel_crypt::ratchets::stacked::StackedRatchet;
    pub use citadel_crypt::ratchets::Ratchet;
    pub use citadel_types::crypto::AlgorithmsExt;
    pub use citadel_types::crypto::SecBuffer;
    pub use citadel_user::account_manager::AccountManager;
    pub use citadel_user::auth::proposed_credentials::ProposedCredentials;
    pub use citadel_user::backend::BackendType;
    pub use citadel_user::external_services::{RtdbConfig, ServicesConfig, ServicesObject};
    pub use citadel_user::prelude::ConnectProtocol;
    pub use citadel_user::server_misc_settings::ServerMiscSettings;

    pub use crate::error::NetworkError;
    pub use crate::functional::*;
    pub use crate::kernel::RuntimeFuture;
    pub use crate::kernel::{
        kernel_executor::KernelExecutor, kernel_trait::NetKernel, KernelExecutorSettings,
    };
    pub use crate::proto::misc::panic_future::ExplicitPanicFuture;
    pub use crate::proto::misc::session_security_settings::SessionSecuritySettingsBuilder;
    pub use crate::proto::misc::underlying_proto::ServerUnderlyingProtocol;
    pub use crate::proto::node::CitadelNode;
    pub use crate::proto::outbound_sender::OutboundUdpSender;
    pub use crate::proto::packet_processor::peer::group_broadcast::GroupBroadcast;
    pub use crate::proto::peer::channel::*;
    pub use crate::proto::peer::group_channel::{
        GroupBroadcastPayload, GroupChannel, GroupChannelRecvHalf, GroupChannelSendHalf,
    };
    pub use crate::proto::peer::peer_layer::NodeConnectionType;
    pub use crate::proto::peer::peer_layer::PeerResponse;
    pub use crate::proto::peer::peer_layer::{PeerConnectionType, PeerSignal};
    pub use crate::proto::remote::Ticket;
    pub use crate::proto::state_container::VirtualTargetType;
    pub use crate::re_imports::{async_trait, NodeType};
    pub use citadel_types::crypto::SecrecyMode;
    pub use citadel_types::proto::ConnectMode;
    pub use citadel_types::proto::MessageGroupKey;
    pub use citadel_user::backend::utils::{ObjectTransferHandler, ObjectTransferHandlerInner};
    pub use citadel_user::serialization::SyncIO;

    #[doc(hidden)]
    pub use crate::proto::misc::net::{safe_split_stream, GenericNetworkStream};
    pub use crate::proto::node_request::*;
    pub use crate::proto::node_result::*;
    pub use crate::proto::remote::*;

    pub use crate::auth::AuthenticationRequest;
    #[doc(hidden)]
    pub use crate::proto::misc::{read_one_packet_as_framed, write_one_packet};
    pub use crate::proto::session::ServerOnlySessionInitSettings;
    pub use citadel_crypt::scramble::streaming_crypt_scrambler::ObjectSource;
    pub use citadel_types::crypto::EncryptionAlgorithm;
    pub use citadel_types::crypto::KemAlgorithm;
    pub use citadel_types::crypto::SecurityLevel;
    pub use citadel_types::crypto::SigAlgorithm;
    pub use citadel_types::proto::GroupType;
    pub use citadel_types::proto::MemberState;
    pub use citadel_types::proto::MessageGroupOptions;
    pub use citadel_types::proto::ObjectTransferOrientation;
    pub use citadel_types::proto::ObjectTransferStatus;
    pub use citadel_types::proto::SessionSecuritySettings;
    pub use citadel_types::proto::TransferType;
    pub use citadel_types::proto::UdpMode;
    pub use citadel_types::proto::VirtualObjectMetadata;
    pub use citadel_types::user::UserIdentifier;
    pub use citadel_user::misc::{prepare_virtual_path, validate_virtual_path, CNACMetadata};
    pub use netbeam::sync::tracked_callback_channel::*;
}

pub mod auth;
/// Contains the constants used by this crate
pub mod constants;
/// The default error type for this crate
mod error;
/// Functional extras
mod functional;
/// For handling differential function input types between single/multi-threaded modes
mod inner_arg;
/// Contains the streams for creating connections
pub mod kernel;
/// The primary module of this crate
mod proto;

pub(crate) type ProtocolRatchetManager<R> = DefaultRatchetManager<NetworkError, R, UserMessage>;
pub type ProtocolMessengerTx<R> = RatchetManagerMessengerLayerTx<NetworkError, R, UserMessage>;
pub type ProtocolMessengerRx<R> = RatchetManagerMessengerLayerRx<NetworkError, R, UserMessage>;
pub type ProtocolMessenger<R> = RatchetManagerMessengerLayer<NetworkError, R, UserMessage>;
