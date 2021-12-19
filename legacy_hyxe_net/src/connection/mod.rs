/// Server
pub mod server;

/// Allows an interface between the [Server] (which every node implicitly is) and client-like subroutines
pub mod client_handle;

/// This module organizes the signals which the [ServerBridgeHandler] ends up processing after receiving the output from the [StageDriver]
pub mod bridge_packet_processor;

/// Every session has access to a granted [ConnectionHandle]. The connection handle guarantees that the data
pub mod session;

/// When a server-based stream is being ran, its job will be to accept new streams which are wrapped via `stream_wrappers`, and then pass t
pub mod server_bridge_handler;

/// The [BridgeHandler] is within each client-based* [Session] for purposes of I/O communication. Outbound data is pushed directly-through to the lower-level
/// [ConnectionHandler], while Inbound data is asynchronously returned via .awaited [ExpectancyResponses].
pub mod bridge_handler;

/// Sometimes, a full-blown bridge is entirely unnecessary. In the case of the registration process, we only need the stream_outbound_tx coupled with the stream_signal_tx
/// to communicate with the stream. Inbound items are automatically received by the [ServerBridgeHandler] in the registration process, and are forwarded to the
/// [RegistrationHandler]
pub mod temporary_bridge;

/// An abstraction for describing the nature of a connection stream (e.g, port #, peer addr, etc)
pub mod connection;

/// Contains tools for managing streams as connections
pub mod stream_wrappers;

/// The server request sink is the high-level networking type that interfaces with the user's low-level API
pub mod server_request_builder;

/// This provides the means of mapping
pub mod network_map;

/// Adds functionality to the [Server] type by allowing for reception and initiation of new clients and servers. Those types can be either in the
/// HyperLAN or HyperWAN; both cases are covered herein
pub mod registration;

/// This submodule adds functionality to the [Server] type by allowing read-only access to the server's client's publicly shared information. The
/// baker's stand is the metaphorical expansion of viewing, selling, and buying data, and is thus suitable for a cryptographic network.
pub mod bakers_stand;

/// Signal for closing the stream_wrapper
pub const STREAM_SHUTDOWN: u8 = 0;
/// Signal for restarting the stream_wrapper
pub const STREAM_RESTART: u8 = 1;