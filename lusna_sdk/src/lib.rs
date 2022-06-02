#![forbid(unsafe_code)]
//! Software development kit for creating high performance, extremely-secure, and post-quantum network applications. Supports p2p (NAT traversal + WebRTC) and standard client/server architectures for
//! messaging and streaming. The underlying asynchronous runtime is [Tokio](https://tokio.rs).
//!
//! The Network protocol, SDK, and user libraries use 100% safe rust
//!
//! All peer-discovery and NAT traversal are built-in to the protocol, with the central server acting as a broker and authenticator. The central server is used for TURN-like routing when direct p2p NAT traversal fails between two nodes.
//!
//! Authentication to a central node is required before making peer-to-peer connections. There is both device-dependent auth as well as credentialed authentication backed by the argon2id hashing algorithm.
//!
//! Client/Peer information is by default synchronized to the local filesystem. If the *enterprise* feature is enabled, a SQL (MySQL, PostgreSQL, SQLite) server or cluster can be used instead.
//!
//! When messaging is used, perfect forward secrecy (PFS) is an optional mode on a per-session basis. Best-effort mode (BEM) is also available if the security of PFS is not needed, and instead, high throughput
//! in messaging is required.
//!
//! Client-to-server connections can use TCP, TLS (default), or QUIC protocols for the underlying communication. Cryptographers recommend the use of hybrid protocols, and as such, TLS is the default to
//! ensure implementations of post-quantum networks are at least as secure as traditional methods. Valid certificates can be specified when constructing the application, otherwise, self-signed certificates are used for the underlying protocol.
//!
//! Peer-to-peer connections only use QUIC. In order to establish a direct peer-to-peer connection, UDP NAT-traversal is required, and as such, the use of QUIC complements this requirement since QUIC uses UDP for ordered, reliable transport.
//!
//! Streaming is also available in this crate. When the use of webrtc is desired for an application, the *webrtc* feature can be enabled to allow interoperability between the [`UdpChannel`] and the [WebRTC.rs](https://webrtc.rs) ecosystem.
//!
//! # Feature Flags
//! - `standard`: Uses a single-threaded !Send executor for the inner protocol
//! - `plus`: Uses a multi-threaded Send executor for the inner protocol
//! - `enterprise-lite`: Uses a single-threaded !Send executor for the inner protocol coupled with an optional SQL backend
//! - `enterprise`: Uses a multi-threaded Send executor for the inner protocol coupled with an optional SQL backend
//! - `webrtc`: enables interoperability with webrtc via the [`UdpChannel`] (see: [UdpChannel::into_webrtc_compat](crate::prelude::UdpChannel::into_webrtc_compat))
//!
//!
//! # Post-quantum key encapsulation mechanisms
//! The user may also select a KEM before a session to either a central server or peer begins (see: [SessionSecuritySettingsBuilder](crate::prelude::SessionSecuritySettingsBuilder)). Each KEM has variants that alter the degree of security
//! - Supersingular isogeny key exchange (SIKE)
//! - Saber (default: Firesaber)
//! - NTRU
//! - Kyber
//!
//! # Symmetric Encryption Algorithms
//! The user may also select a symmetric encryption algorithm before a session starts (see: [SessionSecuritySettingsBuilder](crate::prelude::SessionSecuritySettingsBuilder))
//! - AES-256-GCM-SIV
//! - XChacha20Poly-1305
//!
//! # Executor Architecture: The [`NetKernel`]
//! Any node in the network may act as **both** a server and a client/peer (except for when [`NodeType::Peer`] or the default node type is specified). Since multiple parallel connections may exist, handling events is necessary. When the lower-level protocol produces events,
//! they are sent to the [`NetKernel`]. The [`NetKernel`] is where your application logic must be written.
//!
//! ## Initialization Stage: The [`KernelExecutor`] and the [`NodeRemote`]
//! When the node is built and awaited (as seen in the examples below), the node creates a [`NodeRemote`] which is used to communicate between the [`NetKernel`] and the lower level networking protocol. Then, the [`KernelExecutor`] passes the remote to [`NetKernel::load_remote`] (which uses a mutable reference to
//! the kernel itself to allow mutation of the inner data, effectively ensuring that the remote may be stored without need of atomics, as well as any other config). Thereafter, the [`KernelExecutor`] calls [`NetKernel::on_start`] (uses an ``&self`` reference) where any first asynchronous calls using the remote itself may be made.
//!
//! ## Passive Stage
//! As the protocol generates events, the developer may choose to add program logic to react to the events. When an event is sent from the protocol to the [`KernelExecutor`], the [`KernelExecutor`] executes [`NetKernel::on_node_event_received`], passing the new event. Importantly,
//! every call to [`NetKernel::on_node_event_received`] is executed *concurrently* (**not** to be confused with *parallel*), allowing the developer to react to each event separately without having to await completion before handling the next event. If an error is returned from [`NetKernel::on_node_event_received`], then the [`KernelExecutor`] will attempt
//! a graceful shutdown of the protocol and any running sessions. Errors returned from [`NetKernel::on_node_event_received`] are propagated to the initial awaited call site on the node.
//!
//! Important note: Since [`NetKernel::on_node_event_received`] takes self by reference and is executed concurrently, [`NetKernel`] requires that ``Self: Sync`` since by definition, if ``&T: Send``, then ``T: Sync``
//!
//! ## Shutdown stage
//! Whether through an error, or, a call to [`NodeRemote::shutdown`], the [`KernelExecutor`] will call [`NetKernel::on_stop`] (which is passed an &mut). During and after the execution of [`NetKernel::on_stop`], no more calls to [`NetKernel::on_node_event_received`] will occur. Any errors returned from [`NetKernel::on_stop`] will be propagated
//! to the initial awaited call site on the node. Execution is complete, returning the initial kernel on success
//!
//! # Examples
//!
//! ## Server
//! When building either a client/peer or server node, a [`NetKernel`] is expected. In the case below, an EmptyKernel is used that does no additional processing of inbound connections:
//! ```
//! use lusna_sdk::prelude::*;
//! use std::net::SocketAddr;
//! use std::str::FromStr;
//! use lusna_sdk::prefabs::server::empty_kernel::EmptyKernel;
//!
//! // this server will listen on 127.0.0.1:25021, and will use the built-in defaults. When calling 'build', a NetKernel is specified
//! let server = NodeBuilder::default()
//! .with_node_type(NodeType::Server(SocketAddr::from_str("127.0.0.1:25021").unwrap()))
//! .build(EmptyKernel::default())?;
//!
//! // await the server to execute
//! let result = server.await;
//! ```
//!
//! ## Client/Peer
//! This client will connect to the server above. It will first register (if the account is not yet registered), and thereafter, connect to the server, calling the provided future to handle the received channel
//! ```
//! use lusna_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
//! use std::net::SocketAddr;
//! use std::str::FromStr;
//! use futures::StreamExt;
//! use lusna_sdk::prelude::NodeBuilder;
//!
//! let client_kernel = SingleClientServerConnectionKernel::new_register_defaults("John Doe", "john.doe", "password", SocketAddr::from_str("127.0.0.1:25021").unwrap(), |connect_success, remote| async move {
//!     // handle program logic here
//!     let (sink, mut stream) = connect_success.channel.split();
//!     while let Some(message) = stream.next().await {
//!         // message received in the form of a SecBuffer (memory-protected)
//!     }
//! });
//!
//! let client = NodeBuilder::default().build(client_kernel).unwrap();
//! let result = client.await;
//! ```
//!
//! [`UdpChannel`]: crate::prelude::UdpChannel
//! [`NetKernel`]: crate::prelude::NetKernel
//! [`NetKernel::load_remote`]: crate::prelude::NetKernel::load_remote
//! [`NetKernel::on_start`]: crate::prelude::NetKernel::on_start
//! [`NetKernel::on_node_event_received`]: crate::prelude::NetKernel::on_node_event_received
//! [`NetKernel::on_stop`]: crate::prelude::NetKernel::on_stop
//! [`KernelExecutor`]: crate::prelude::KernelExecutor
//! [`NodeRemote`]: crate::prelude::NodeRemote
//! [`NodeRemote::shutdown`]: crate::prelude::NodeRemote::shutdown
//! [`NodeType`]: crate::prelude::NodeType
//! [`NodeType::Peer`]: crate::prelude::NodeType::Peer

#![deny(
clippy::cognitive_complexity,
trivial_numeric_casts,
unused_extern_crates,
unused_import_braces,
variant_size_differences,
unused_features,
unused_results,
)]

/// Convenience import for building applications
pub mod prelude {
    pub use hyxe_net::prelude::*;
    pub use crate::prefabs::client::PrefabFunctions;
    pub use crate::builder::node_builder::*;
    pub use crate::remote_ext::*;
    pub use crate::responses;
}

/// Extension implementations endowed upon the [NodeRemote](crate::prelude::NodeRemote)
pub mod remote_ext;
/// A list of prefabricated kernels designed for common use cases. If a greater degree of control is required for an application, a custom implementation of [NetKernel](crate::prelude::NetKernel) is desirable
pub mod prefabs;
mod builder;
/// For easy construction of replies to common message types
pub mod responses;
#[doc(hidden)]
pub mod test_common;