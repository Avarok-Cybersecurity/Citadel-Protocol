//! Reading a message an older or newer node wrote: see [`citadel_types::wire_compat`], where
//! the helper lives so that types defined below this crate can use it too.

pub use citadel_types::wire_compat::ok_or_default;
