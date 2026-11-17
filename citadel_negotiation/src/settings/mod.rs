//! The settings this crate negotiates. Each is its own file with its own merge-law tests.

mod key_profile;
mod media;
mod transfer_mode;

pub use key_profile::KeyProfile;
pub use media::{MediaTransport, MediaTransportKind};
pub use transfer_mode::TransferMode;
