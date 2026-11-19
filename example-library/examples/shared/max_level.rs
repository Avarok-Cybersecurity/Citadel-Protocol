//! The maximum security level an example node builds a link with. Every node requires one: the
//! SDK has no default. `Extreme` (five layers) is the highest named level; a level read from a
//! peer, the server or a registration above it is refused before anything is built.

use citadel_sdk::prelude::{MaxSecurityLevel, SecurityLevel};

pub fn extreme() -> MaxSecurityLevel {
    MaxSecurityLevel::new(SecurityLevel::Extreme).expect("Extreme is a level a ratchet can carry")
}
