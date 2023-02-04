/// A kernel that accepts all inbound file transfer requests for basic file transfers
/// AND RE-VFS transfers
pub mod accept_file_transfer_kernel;
/// A kernel that reacts to new channels created, allowing communication with new clients.
/// Useful for when a server needs to send messages to clients
pub mod client_connect_listener;
/// A non-reactive kernel that does no additional processing on top of the protocol
pub mod empty;
