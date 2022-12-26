/// For the custom BytesCodec that doesn't overflow
pub(crate) mod codec;
///
pub(crate) mod endpoint_crypto_accessor;
pub(crate) mod misc;
/// Used at each HyperNode
pub mod node;
pub mod node_request;
pub mod node_result;
/// A cloneable handle for sending data through UDP ports
pub(crate) mod outbound_sender;
/// The fundamental packet types
pub(crate) mod packet;
/// For creating specific packet types
pub(crate) mod packet_crafter;
/// Contains the library for processing inbound packet types. all #[inline]'d
pub(crate) mod packet_processor;
///
pub(crate) mod peer;
pub mod remote;
/// Each CID gets a session
pub(crate) mod session;
/// Manages multiple sessions
pub(crate) mod session_manager;
pub(crate) mod session_queue_handler;
/// For keeping track of the stages of different processes
pub(crate) mod state_container;
/// For organizing the stage containers
pub(crate) mod state_subcontainers;
/// ~!
pub(crate) mod transfer_stats;
/// Packet validations. This is not the same as encryption
pub(crate) mod validation;
