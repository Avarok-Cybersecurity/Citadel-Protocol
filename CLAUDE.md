# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Essential Commands

### Building and Testing
```bash
# Install development dependencies
cargo make install

# Build the project
cargo build

# Run local tests (without SQL/Redis backends)
cargo make test-local

# Run comprehensive tests (requires SQL/Redis setup)
# Set TESTING_SQL_SERVER_ADDR_CLIENT and TESTING_SQL_SERVER_ADDR_SERVER env vars first
cargo make test

# Run specific test
cargo nextest run <test_name>

# Format code
cargo make fmt

# Run clippy checks
cargo make check

# Generate documentation
cargo make docs
```

### Running Examples
```bash
# First, always start a server
export CITADEL_SERVER_ADDR="127.0.0.1:25000"
cargo run --example server_basic

# Then run clients in another terminal
cargo run --example client_echo

# For P2P examples
export CITADEL_MY_USER="user1"
export CITADEL_OTHER_USER="user2"
cargo run --example chat
```

## Architecture Overview

### Workspace Structure
The Citadel Protocol is a Rust workspace with these core crates:
- **citadel_sdk**: Main SDK and public API
- **citadel_proto**: Core protocol implementation and networking
- **citadel_wire**: Wire protocol and transport layer abstractions
- **citadel_crypt**: Cryptographic primitives and post-quantum algorithms
- **citadel_user**: User management and authentication
- **citadel_io**: I/O abstractions for cross-platform support
- **citadel_types**: Common types shared across crates
- **netbeam**: NAT traversal and hole-punching utilities
- **citadel_pqcrypto**: Post-quantum cryptography implementations

### Key Architectural Concepts

**Protocol Layers**: The protocol implements a multi-layered security architecture with:
- Multiple independent key exchanges using post-quantum KEMs (Kyber, NTRU)
- Per-message ratcheting for perfect forward secrecy
- Configurable security modes (PFS vs Best-effort)

**Node Types**:
- **Server nodes**: Accept incoming connections, manage user registration
- **Client nodes**: Connect to servers, can be credentialed or transient
- **Peer nodes**: Direct P2P connections after initial server-mediated handshake

**Networking Abstractions**:
- Uses `GenericNetworkStream` and `GenericNetworkListener` traits to abstract over TCP, TLS, QUIC
- Built-in NAT traversal using STUN/TURN protocols
- UDP hole-punching for P2P connections

**Threading Modes**:
- Single-threaded (default): Low latency, minimal memory footprint
- Multi-threaded (feature flag): Higher throughput for concurrent connections

## Current Development Focus

### Citadel Nexus Initiative
The codebase is being refactored to abstract I/O operations (see CITADEL_NEXUS.md). This involves:
- Creating a `CitadelProtocolIOFunctions` trait to abstract networking operations
- Enabling WASM compilation for web browser support
- Maintaining backward compatibility with existing implementations

## Important Patterns

**Kernel Pattern**: Applications use "kernels" to handle connection logic:
```rust
let kernel = SingleClientServerConnectionKernel::new(
    server_settings,
    |connect_success, remote| async move { /* handler */ }
)?;
```

**Builder Pattern**: Most components use builders for configuration:
```rust
NodeBuilder::default()
    .with_node_type(NodeType::server(addr)?)
    .build(kernel)?
```

**Remote Virtual Filesystem (RE-VFS)**: Files are encrypted locally and stored remotely, with keys never leaving the client.

## Testing Considerations
- Tests require `localhost-testing` feature for local network testing
- External backend tests need Redis/SQL servers configured via environment variables
- Use `cargo make test-local` for quick local testing without external dependencies
- Multi-threaded tests use the `multi-threaded` feature flag