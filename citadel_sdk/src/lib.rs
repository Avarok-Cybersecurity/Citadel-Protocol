#![doc(html_logo_url = "avarok.png", html_favicon_url = "favicon.png")]
//! Software development kit for creating high performance, extremely-secure, and post-quantum network applications. Supports p2p (NAT traversal + WebRTC) and standard client/server architectures for
//! messaging and streaming. The underlying asynchronous runtime is [Tokio](https://tokio.rs).
//!
//! The Network protocol, SDK, and user libraries use 100% safe rust
//!
//! All peer-discovery and NAT traversal are built-in to the protocol, with the central server acting as a broker and authenticator. The central server is used for TURN-like routing when direct p2p NAT traversal fails between two nodes.
//!
//! Authentication to a central node is required before making peer-to-peer connections. There is both device-dependent auth as well as credentialed authentication backed by the argon2id hashing algorithm.
//!
//! Client/Peer information is by default synchronized to the local filesystem. If the *redis* and/or *sql* feature is enabled, a redis or SQL (MySQL, PostgreSQL, SQLite) server or cluster can be used instead.
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
//! - `multi-threaded`: Uses a multi-threaded (Send) executor for the inner protocol
//! - `redis`: Enables the use of Redis for the backend
//! - `sql`: Enables the use of sql for the backend
//! - `webrtc`: enables *limited* interoperability with webrtc via the [`UdpChannel`] (see: [UdpChannel::into_webrtc_compat](crate::prelude::UdpChannel::into_webrtc_compat))
//!
//!
//! # Post-quantum key encapsulation mechanisms
//! The user may also select a KEM family before a session to either a central server or peer begins (see: [SessionSecuritySettingsBuilder](crate::prelude::SessionSecuritySettingsBuilder)). Each KEM has variants that alter the degree of security
//! - Kyber (default)
//!
//! # Encryption Algorithms
//! The user may also select a symmetric encryption algorithm before a session starts (see: [SessionSecuritySettingsBuilder](crate::prelude::SessionSecuritySettingsBuilder))
//! - AES-256-GCM-SIV
//! - XChacha20Poly-1305
//! - Kyber "scramcryption" (see below for explanation)
//!
//! Whereas AES-GCM and ChaCha are only quantum resistant (as opposed to post-quantum), a novel method of encryption may be used that
//! combines the post-quantum asymmetric encryption algorithm Kyber coupled with AES. When Kyber "scramcryption" is used, several modifications to the protocol outlined in the whitepaper
//! is applied. The first modification is the use of Falcon-1024 to sign each message to ensure non-repudiation. The second modification is more complex. Ciphertext is first encrypted by AES-GCM, then, randomly shifted using modular arithmetic
//! in 32-byte blocks using a 32-byte long quasi one-time pad (OTP). The OTP is unique for each ciphertext, and, is appended at the end of the ciphertext in encrypted form (using Kyber1024 encryption). Even if the attacker uses Grover's algorithm to
//! discover the AES key, the attacker would also have to break the lattice-based Kyber cryptography in order to properly order
//! the ciphertext before using the AES key. Since every 32 bytes of input into the Kyber encryption scheme produces over a 1KB output ciphertext, and, each quasi-OTP is 32 bytes long,
//! the size of each packet is increased at a minimum constant value, helping keep packet sizes minimal and security very high.
//!
//! # Network Architecture
#![cfg_attr(
    feature = "doc-images",
    doc = ::embed_doc_image::embed_image!(
    "network_direct_p2p",
    "../resources/network_direct_p2p.png"
    )
)]
//! ![Network Architecture w/ direct P2P][network_direct_p2p]
//! Each network has a central node that peers may connect to. This central node helps facilitate P2P connections, and, can itself serve
//! as a peer on a network if the program implementation on the central server so chooses.
//!
//! The peers Alice and Bob can only connect to each other after they use the central server to **register** to each other. Once registered, the two peers
//! may begin attempting connecting to each other via NAT traversal. Each peer begins NAT traversal by attempting to determine what type of NAT
//! they're each behind by communicating to 3 different STUN servers to find a predictable pattern in their internal/external socket mappings.
//! If at least one has a predictable pattern, a direct P2P connection bypassing the central server may be facilitated.
//!
//! If, however, both Alice and Bob do not have predictable internal/external socket mappings (e.g., both are behind symmetric NATs), then, both will use
//! their central server to relay their packets to each other using endpoint to endpoint encryption, preventing the central server from
//! decrypting the packets.
//!
#![cfg_attr(
    feature = "doc-images",
    doc = ::embed_doc_image::embed_image!(
    "network_relay_p2p",
    "../resources/network_relay_p2p.png"
    )
)]
//! ![Network Architecture w/ relay P2P][network_relay_p2p]
//!
//!
//! # Executor Architecture: The [`NetKernel`]
#![cfg_attr(
    feature = "doc-images",
    doc = ::embed_doc_image::embed_image!(
        "proto_kernel_iface",
        "../resources/proto_kernel_iface.png"
    )
)]
//! ![Protocol/Executor/NetKernel Architecture][proto_kernel_iface]
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
//! use citadel_sdk::prelude::*;
//! use citadel_sdk::prefabs::server::empty::EmptyKernel;
//!
//! // this server will listen on 127.0.0.1:25021, and will use the built-in defaults. When calling 'build', a NetKernel is specified
//! let server = NodeBuilder::default()
//! .with_node_type(NodeType::server("127.0.0.1:25021")?)
//! .build(EmptyKernel::default())?;
//!
//! // await the server to execute
//! # async move {
//! let result = server.await;
//! # };
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Client/Peer
//! This client will connect to the server above. It will first register (if the account is not yet registered), and thereafter, connect to the server, calling the provided future to handle the received channel
//! ```
//! use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
//! use futures::StreamExt;
//! use citadel_sdk::prelude::NodeBuilder;
//!
//! let client_kernel = SingleClientServerConnectionKernel::new_register_defaults("John Doe", "john.doe", "password", "127.0.0.1:25021", |connect_success, remote| async move {
//!     // handle program logic here
//!     let (sink, mut stream) = connect_success.channel.split();
//!     while let Some(message) = stream.next().await {
//!         // message received in the form of a SecBuffer (memory-protected)
//!     }
//!
//!     Ok(())
//! })?;
//!
//! let client = NodeBuilder::default().build(client_kernel)?;
//! # async move {
//! let result = client.await;
//! # };
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Remote Encrypted Virtual Filesystem (RE-VFS)
//! The RE-VFS allows clients, servers, and peers to treat each other as remote endpoints for encrypted file storage.
//! Since encrypting data locally using a symmetric key poses a vulnerability if the local node is compromised, The
//! Citadel Protocol solves this issue by using a local 1024-Kyber public key to encrypt the data (via Kyber scramcryption for
//! keeping the data size to a minimum), then, sending the contents to the adjacent endpoint. By doing this, the private decryption
//! key and the contents are kept separate, forcing the hacker to compromise both endpoints.
//!
//! In order to use the RE-VFS, both endpoints must use the Filesystem backend. Second, the endpoint serving as a storage point
//! must accept the inbound file transfer requests, otherwise, the transfer will fail. The example below for the receiving endpoint
//! shows how to auto-accept inbound file transfer requests
//!
//! # Examples
//!
//! ## Receiving endpoint
//! ```
//! use citadel_sdk::prelude::*;
//! use citadel_sdk::prefabs::server::accept_file_transfer_kernel::AcceptFileTransferKernel;
//!
//! // this server will listen on 127.0.0.1:25021, and will use the built-in defaults with a kernel
//! // that auto-accepts inbound file transfer requests
//! let server = NodeBuilder::default()
//! .with_node_type(NodeType::server("127.0.0.1:25021")?)
//! .build(AcceptFileTransferKernel::default())?;
//!
//! // await the server to execute
//! # async move {
//! let result = server.await;
//! # };
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Sending endpoint
//! ```
//! use citadel_sdk::prefabs::client::single_connection::SingleClientServerConnectionKernel;
//! use futures::StreamExt;
//! use citadel_proto::prelude::*;
//! use citadel_sdk::prelude::NodeBuilder;
//!
//! let client_kernel = SingleClientServerConnectionKernel::new_register_defaults("John Doe", "john.doe", "password", "127.0.0.1:25021", |connect_success, remote| async move {
//!     let virtual_path = "/home/virtual_user/output.pdf";
//!     // write the contents with reinforced security.
//!     citadel_sdk::fs::write_with_security_level(&mut remote, "../path/to/input.pdf", SecurityLevel::Reinforced, virtual_path).await?;
//!     // read the contents. Reading downloads the file to a local path
//!     let stored_local_path = citadel_sdk::fs::read(&mut remote, virtual_path).await?;
//!  
//!     Ok(())
//! })?;
//!
//! let client = NodeBuilder::default().build(client_kernel)?;
//! # async move {
//! let result = client.await;
//! # };
//! # Ok::<(), Box<dyn std::error::Error>>(())
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
//! [`PeerConnectionType`]: crate::prelude::PeerConnectionType
#![cfg_attr(not(feature = "localhost-testing"), deny(unsafe_code))]
#![deny(
    clippy::cognitive_complexity,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    variant_size_differences,
    unused_features,
    unused_results
)]

/// Convenience import for building applications
pub mod prelude {
    pub use crate::backend_kv_store::BackendHandler;
    pub use crate::builder::node_builder::*;
    pub use crate::prefabs::client::peer_connection::PeerConnectionSetupAggregator;
    pub use crate::prefabs::client::PrefabFunctions;
    pub use crate::remote_ext::user_ids::*;
    pub use crate::remote_ext::*;
    pub use crate::responses;
    pub use citadel_proto::prelude::*;
}

/// Store data to the backend using this library
pub mod backend_kv_store;
mod builder;
/// Convenience functions for interacting with the remote encrypted virtual filesystem (RE-VFS)
pub mod fs;
/// A list of prefabricated kernels designed for common use cases. If a greater degree of control is required for an application, a custom implementation of [NetKernel](crate::prelude::NetKernel) is desirable
pub mod prefabs;
/// Extension implementations endowed upon the [NodeRemote](crate::prelude::NodeRemote)
pub mod remote_ext;
/// For easy construction of replies to common message types
pub mod responses;
#[doc(hidden)]
pub mod test_common;

#[macro_use]
pub(crate) mod macros;
/// Convenience for SDK users
pub use citadel_proto::prelude::async_trait;
