# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Building
```bash
# Build all packages
cargo build --all

# Build with specific features
cargo build --features sql,redis

# Build release version
cargo build --release
```

### Testing
```bash
# Run local tests (without external backends)
cargo make test-local

# Run comprehensive tests (requires SQL/Redis setup)
# Set environment variables first:
export TESTING_SQL_SERVER_ADDR_CLIENT="mysql://root:password@localhost/hyxewave2,postgres://nologik:password@localhost/hyxewave2,sqlite:/home/runner/hyxewave2.db,redis://127.0.0.1:6379/2"
export TESTING_SQL_SERVER_ADDR_SERVER="mysql://root:password@localhost/hyxewave,postgres://nologik:password@localhost/hyxewave,sqlite:/home/runner/hyxewave.db,redis://127.0.0.1:6379/1"
cargo make test

# Run specific package tests
cargo nextest run --package citadel_sdk --features=localhost-testing

# Run multi-threaded tests
cargo nextest run --package citadel_sdk --features=multi-threaded,localhost-testing

# Run a single test
cargo nextest run test_name_here
```

### Linting and Formatting
```bash
# Format code
cargo make fmt

# Run clippy
cargo make clippy

# Run comprehensive checks (format + clippy)
cargo make check

# Full PR validation
cargo make pr
```

### Documentation
```bash
# Generate documentation
cargo make docs

# Generate docs with WebRTC support
cargo doc --package citadel_sdk --features=webrtc,doc-images --no-deps --release
```

### Coverage
```bash
# Generate HTML coverage report
cargo make cov --html

# Generate LCOV report for CI
cargo make cov --lcov
```

## Architecture Overview

### Workspace Structure
The project is organized as a Rust workspace with multiple interconnected crates:

- **citadel_sdk**: Main SDK crate providing high-level APIs for building secure network applications
- **citadel_proto**: Core protocol implementation handling networking, encryption, and session management
- **citadel_crypt**: Cryptographic primitives including ratcheting algorithms, encryption toolsets, and key management
- **citadel_pqcrypto**: Post-quantum cryptography implementations (Kyber, NTRU)
- **citadel_wire**: NAT traversal and network transport layer (TCP, TLS, QUIC)
- **citadel_user**: User management and authentication
- **citadel_types**: Common types and utilities
- **citadel_io**: Platform-specific I/O abstractions
- **netbeam**: Network utility library for channels and synchronization
- **async_ip**: Asynchronous IP utilities
- **firebase-rtdb**: Firebase real-time database integration
- **example-library**: Example applications demonstrating usage

### Key Architectural Concepts

#### 1. Kernel Pattern
The protocol uses a "kernel" pattern for handling network events and application logic:
- `KernelExecutor` manages the event loop
- Applications implement `NetKernel` trait to handle events
- Pre-built kernels like `SingleClientServerConnectionKernel` for common patterns

#### 2. Multi-layered Security
- **Ratcheting**: Patent-pending 3D matrix ratcheting algorithm in `citadel_crypt/src/ratchets/`
- **Encryption Layers**: Multiple independent encryption layers with different algorithms
- **Security Modes**: 
  - Perfect Forward Secrecy (PFS) - per-message rekeying
  - Best-effort Mode (BEM) - optimized for throughput

#### 3. Transport Abstraction
- Unified interface over TCP, TLS, and QUIC protocols
- Automatic protocol selection based on connection type
- Built-in NAT traversal using STUN/TURN

#### 4. Remote Encrypted Virtual Filesystem (RE-VFS)
- Encrypted storage on remote nodes
- Physical separation of data and decryption keys
- Located in `citadel_sdk/src/fs/`

### Threading Models

#### Single-threaded (Default)
- Uses `!Send` types for zero-cost abstractions
- Optimal for low-latency, memory-constrained environments
- All async operations run on single thread

#### Multi-threaded (Feature: `multi-threaded`)
- Uses `Send` types allowing work across threads
- Better for high-throughput server applications
- Enabled via feature flag in Cargo.toml

### Backend Storage Options
Configured through feature flags:
- **Filesystem** (default): Local file storage
- **Redis** (`redis` feature): Distributed caching
- **SQL** (`sql` feature): MySQL, PostgreSQL, SQLite support

### Security Considerations
- All cryptographic operations use verified implementations from OQS and PQClean
- Automatic zeroization of sensitive data via `zeroize` crate
- Constant-time operations where applicable
- No hardcoded credentials or keys

### Common Development Patterns

#### Creating a Server
```rust
use citadel_sdk::prelude::*;

let server = NodeBuilder::default()
    .with_node_type(NodeType::server("127.0.0.1:25021")?)
    .build(kernel)?;
```

#### Creating a Client
```rust
use citadel_sdk::prelude::*;

let client = NodeBuilder::default()
    .with_node_type(NodeType::client())
    .build(kernel)?;
```

#### Custom Security Settings
```rust
let settings = SessionSecuritySettingsBuilder::default()
    .with_crypto_params(KemAlgorithm::Kyber + EncryptionAlgorithm::AES256GCM)
    .with_security_level(SecurityLevel::Standard)
    .build()?;
```

### Testing Guidelines
- Use `localhost-testing` feature for local development
- Mock external dependencies when possible
- Test both single-threaded and multi-threaded modes
- Ensure tests clean up resources properly

### Performance Optimization
- Prefer `BytesMut` for zero-copy operations
- Use object pools for frequently allocated objects
- Profile with `cargo flamegraph` for bottlenecks
- Consider BEM mode for high-throughput scenarios

<!-- CI noop: trigger pipeline rerun -->
