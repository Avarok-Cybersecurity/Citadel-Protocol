/// Used at each HyperNode
pub mod hdp_node;
/// The fundamental packet types
pub(crate) mod hdp_packet;
/// Contains the library for processing inbound packet types. all #[inline]'d
pub(crate) mod packet_processor;
/// Manages multiple sessions
pub(crate) mod hdp_session_manager;
/// Each CID gets a session
pub(crate) mod hdp_session;
/// Packet validations. This is not the same as encryption
pub(crate) mod validation;
/// For creating specific packet types
pub(crate) mod hdp_packet_crafter;
/// ~!
pub(crate) mod time;
/// For keeping track of the stages of different processes
pub(crate) mod state_container;
/// For the custom BytesCodec that doesn't overflow
pub(crate) mod codec;
/// For organizing the stage containers
pub(crate) mod state_subcontainers;
/// A cloneable handle for sending data through UDP ports
pub(crate) mod outbound_sender;
///
pub(crate) mod peer;
///
pub(crate) mod endpoint_crypto_accessor;
pub(crate) mod session_queue_handler;
pub(crate) mod misc;