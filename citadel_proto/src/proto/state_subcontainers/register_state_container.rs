/*!
# Registration State Container Module

This module manages the state of user registration processes in the Citadel Protocol, handling registration stages and cryptographic setup.

## Features
- **Stage Management**: Tracks registration process stages
- **Cryptographic Setup**: Manages ratchet construction
- **Timing Control**: Monitors registration packet timing
- **Failure Handling**: Manages registration failures
- **Passwordless Support**: Handles passwordless registration

## Core Components
- `RegisterState`: Main structure for registration state
- `StackedRatchetConstructor`: Handles cryptographic setup
- `StackedRatchet`: Provides secure communication
- `packet_flags`: Defines registration stages

## Example Usage
```rust
use citadel_proto::proto::state_subcontainers::RegisterState;

// Create new registration state
let mut state = RegisterState::default();

// Handle registration packet
state.on_register_packet_received();

// Handle registration failure
state.on_fail();

// Create state from specific stage
let stage_state = RegisterState::from(stage_number);
```

## Important Notes
1. Registration stages must follow proper sequence
2. Cryptographic setup is essential for security
3. Packet timing is tracked for timeout handling
4. Failed registrations clear cryptographic state

## Related Components
- `connect_state_container`: Handles post-registration connection
- `peer_kem_state_container`: Manages key exchange
- `packet_processor`: Uses registration state
- `state_container`: Parent state management

*/

use citadel_io::tokio::time::Instant;

use crate::proto::packet::packet_flags;
use citadel_crypt::stacked_ratchet::constructor::StackedRatchetConstructor;
use citadel_crypt::stacked_ratchet::StackedRatchet;

/// These values should correlate directly to the packet_flags::cmd::aux::do_register::*
#[derive(Default)]
pub struct RegisterState {
    pub(crate) last_stage: u8,
    pub(crate) constructor: Option<StackedRatchetConstructor>,
    pub(crate) created_hyper_ratchet: Option<StackedRatchet>,
    pub(crate) last_packet_time: Option<Instant>,
    pub(crate) passwordless: Option<bool>,
}

impl RegisterState {
    /// When the registration stage fails along any step, call this closure
    pub fn on_fail(&mut self) {
        self.last_stage = packet_flags::cmd::aux::do_register::FAILURE;
        self.constructor = None;
        self.on_register_packet_received();
    }

    /// At the end of every stage, this should be called
    pub fn on_register_packet_received(&mut self) {
        self.last_packet_time = Some(Instant::now());
    }
}

impl From<u8> for RegisterState {
    fn from(stage: u8) -> Self {
        Self {
            last_stage: stage,
            ..Default::default()
        }
    }
}
