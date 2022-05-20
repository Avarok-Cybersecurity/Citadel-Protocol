/// A kernel that only makes a single client-to-server connection
pub mod single_connection;
/// A kernel that assists in allowing multiple possible peer-to-peer connections
pub mod peer_connection;
/// A kernel that assists in creating and/or connecting to a group
pub mod broadcast;