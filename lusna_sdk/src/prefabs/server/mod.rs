/// A kernel that reacts to new channels created, allowing communication with new clients.
/// Useful for when a server needs to send messages to clients
pub mod client_connect_listener;
/// A non-reactive kernel that does no additional processing on top of the protocol
pub mod empty;
