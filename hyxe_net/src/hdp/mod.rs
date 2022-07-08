/// For the custom BytesCodec that doesn't overflow
pub(crate) mod codec;
///
pub(crate) mod endpoint_crypto_accessor;
/// Used at each HyperNode
pub mod hdp_node;
/// The fundamental packet types
pub(crate) mod hdp_packet;
/// For creating specific packet types
pub(crate) mod hdp_packet_crafter;
/// Each CID gets a session
pub(crate) mod hdp_session;
/// Manages multiple sessions
pub(crate) mod hdp_session_manager;
pub(crate) mod misc;
/// A cloneable handle for sending data through UDP ports
pub(crate) mod outbound_sender;
/// Contains the library for processing inbound packet types. all #[inline]'d
pub(crate) mod packet_processor;
///
pub(crate) mod peer;
pub(crate) mod session_queue_handler;
/// For keeping track of the stages of different processes
pub(crate) mod state_container;
/// For organizing the stage containers
pub(crate) mod state_subcontainers;
/// ~!
pub(crate) mod time;
/// Packet validations. This is not the same as encryption
pub(crate) mod validation;
