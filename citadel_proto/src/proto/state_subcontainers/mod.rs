/*!
# State Subcontainers Module

This module implements specialized state containers for managing different aspects of connection lifecycle in the Citadel Protocol.

## Features
- **Connection State Management**: Tracks various connection states and transitions
- **Key Exchange Management**: Handles cryptographic key exchange states
- **Registration Flow**: Manages user registration and authentication states
- **State Persistence**: Maintains state across connection phases
- **Timeout Handling**: Manages timeouts and expiry for different states

## Submodules
- `connect_state_container`: Manages active connection states
- `peer_kem_state_container`: Handles peer key exchange states
- `preconnect_state_container`: Manages pre-connection setup
- `register_state_container`: Handles registration states
- `deregister_state_container`: Manages deregistration process
- `rekey_container`: Handles key rotation states
- `meta_expiry_container`: Manages state expiration

## Important Notes
1. Each state container manages a specific phase of connection
2. State transitions should be handled atomically
3. Proper cleanup is essential for state containers
4. Timeouts are used to prevent stale states

## Related Components
- `session`: Uses state containers for session management
- `packet_processor`: Interacts with states during packet processing
- `peer`: Uses states for peer connection management
- `remote`: Manages remote connection states

*/

pub mod connect_state_container;
pub mod deregister_state_container;
pub mod meta_expiry_container;
pub mod peer_kem_state_container;
pub mod preconnect_state_container;
pub mod register_state_container;
pub mod rekey_container;
