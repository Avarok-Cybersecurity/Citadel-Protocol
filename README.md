![](./resources/logo.png)

[![Website shields.io](https://img.shields.io/website-up-down-green-red/http/shields.io.svg)](https://avarok.net)
[![Crates.io](https://img.shields.io/crates/v/citadel_sdk.svg)](https://crates.io/crates/citadel_sdk)
[![codecov](https://codecov.io/gh/Avarok-Cybersecurity/Citadel-Protocol/branch/master/graph/badge.svg?token=J739KOHOZR)](https://app.codecov.io/gh/Avarok-Cybersecurity/Citadel-Protocol)
[![Build docs](https://github.com/Avarok-Cybersecurity/Citadel-Protocol/actions/workflows/deploy.yml/badge.svg)](https://avarok-cybersecurity.github.io/Citadel-Protocol/docs/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)
![Downloads](https://img.shields.io/crates/d/citadel_sdk?style=flat-square)
[![Upload Coverage Report](https://github.com/Avarok-Cybersecurity/Citadel-Protocol/actions/workflows/upload_cov.yaml/badge.svg)](https://github.com/Avarok-Cybersecurity/Citadel-Protocol/actions/workflows/upload_cov.yaml)

## 🌍 Platform Support
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![macOS](https://img.shields.io/badge/mac%20os-000000?style=for-the-badge&logo=macos&logoColor=F0F0F0)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![iOS](https://img.shields.io/badge/iOS-000000?style=for-the-badge&logo=ios&logoColor=white)
![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)

# 🏰 Citadel Protocol

A post-quantum secure networking protocol that makes developing hyper-secure client-server and P2P applications easy. Built with 100% safe Rust, it provides a robust foundation for creating secure, high-performance network applications with built-in NAT traversal and post-quantum cryptography using a very low memory footprint.

## 📑 Table of Contents
- [🌟 Key Features](#-key-features)
- [🚀 Quick Start](#-quick-start)
- [🔒 Security Architecture](#-security-architecture)
- [📂 Remote Encrypted Virtual Filesystem](#-remote-encrypted-virtual-filesystem)
- [⚡ Threading Modes](#-threading-modes)
- [💾 Backend Storage](#-backend-storage)
- [📚 Documentation](#-documentation)
- [📜 Patent and Open Source](#-patent-and-open-source-commitment)
- [🧪 Testing](#-testing)
- [🛡️ Security Considerations](#️-security-considerations)
- [🤝 Contributing](#-contributing)
- [⚖️ License](#️-license)
- [📞 Contact](#-contact)
- [🎯 Examples](#-examples)

## 🌟 Key Features

- 🔒 [Advanced Post-Quantum Security](#-advanced-post-quantum-security) - Novel multi-layered ratcheting algorithm
- 🛡️ [Customizable Security Modes](#️-security-modes) - Balance between security and performance
- 📂 [Remote Encrypted Virtual Filesystem](#-remote-encrypted-virtual-filesystem) - Secure remote storage solution
- ⚡ [Flexible Threading Modes](#-threading-modes) - Single and multi-threaded operation
- 💾 [Multiple Backend Options](#-backend-storage) - Various storage solutions
- 🌐 Built-in NAT Traversal - No port forwarding required
- 📱 Cross-Platform Support - Run anywhere
- 🚀 High Performance - Low latency, minimal resource usage
- 🔍 Zero Trust Architecture - End-to-end encryption

## 🔐 Advanced Post-Quantum Security

Multiple Key Encapsulation Mechanism (KEM) families:
- [Kyber](https://pq-crystals.org/kyber/) (default) - NIST standardized
- [NTRU](https://ntru.org/) (Sntrup761)

Novel Multi-layered Security Architecture:
- [Patent-pending (allowed)](#-patent-and-open-source-commitment) 3D matrix ratcheting algorithm
- Per-message re-keying mechanism
- Multi-layered key exchange protocol
- Multi-layered encryption with customizable algorithms
- Encryption algorithms:
  - AES-256-GCM
  - ChaCha20-Poly1305
  - [Ascon-80pq](https://ascon.iaik.tugraz.at/)
  - Novel Kyber "scramcryption" for enhanced security
- [Customizable Security Modes](#️-security-modes):
  - *True* Perfect Forward Secrecy (PFS) mode with advanced ratcheting
  - Best-effort Mode (BEM) for high-throughput scenarios
  - Configurable security levels and algorithm combinations

## 🌐 Flexible Network Architecture
- [Client-Server and P2P support](#-quick-start)
- Built-in NAT traversal with STUN/TURN capabilities
- Multiple transport protocols:
  - TCP
  - TLS (default)
  - [QUIC](https://www.chromium.org/quic/)
- [WebRTC](https://webrtc.org/) compatibility (optional feature)

## ⚡ Advanced Features
- [Remote Encrypted Virtual Filesystem (RE-VFS)](#-remote-encrypted-virtual-filesystem)
- [Device-dependent and credential-based authentication](#-security-architecture)
- Automatic peer discovery

## 💾 [Backend Storage Options](#-backend-storage)
- Local filesystem (default)
- [Redis](https://redis.io/) support
- SQL support ([MySQL](https://www.mysql.com/), [PostgreSQL](https://www.postgresql.org/), [SQLite](https://www.sqlite.org/))

## 🚀 Quick Start

### 📋 Prerequisites

- Rust toolchain
- OpenSSL
- Clang

### 📥 Installation

1. Add to your `Cargo.toml`:
```toml
[dependencies]
citadel_sdk = "latest_version"
```

2. Setup the development environment:
```bash
cargo make install
```

### 💻 Basic Usage

#### 🖥️ Server Example
```rust
use citadel_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = NodeBuilder::default()
        .with_node_type(NodeType::server("127.0.0.1:25021")?)
        .build(EmptyKernel::default())?;
    
    server.await?;
    Ok(())
}
```

#### 📱 Client Example
```rust
use citadel_sdk::prelude::*;
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create server connection settings
    let server_connection_settings = ServerConnectionSettingsBuilder::credentialed_registration(
        "127.0.0.1:12345",
        "my_username",
        "My Name",
        "notsecurepassword",
    )
    .build()?;

    // Create client kernel
    let kernel = SingleClientServerConnectionKernel::new(
        server_connection_settings,
        |connect_success, remote| async move {
            let (sink, mut stream) = connect_success.channel.split();
            while let Some(message) = stream.next().await {
                // Handle incoming messages
            }
            Ok(())
        }
    )?;

    // Execute the application
    NodeBuilder::default().build(client_kernel)?.await?;
    Ok(())
}
```

## 🔒 Security Architecture

The Citadel Protocol implements a novel multi-layered security approach that goes beyond traditional encryption methods:

### 🔄 Multi-layered Ratcheting
- Implements an advanced patent-pending (allowed as of Dec 2024) ratcheting algorithm that operates across multiple security layers
- Each layer maintains its own independent key schedule
- Provides enhanced forward secrecy by frequently rotating keys at different intervals
- Resistant against quantum attacks through post-quantum primitives

### 🛡️ Security Modes
- *True* Perfect Forward Secrecy (PFS):
  - Enforces re-keying on a per-message basis
  - Guarantees maximum security for messaging applications
  - Each message uses a new key derived from the previous state
  - Complete forward secrecy at message granularity
- Best-effort Mode (BEM):
  - Optimized for high-performance scenarios
  - Re-keys as frequently as possible without blocking message transmission
  - Maintains security while prioritizing throughput
  - Ideal for streaming and high-bandwidth applications

### 🔑 Multi-layered Key Exchange
- Multiple independent key exchanges occur simultaneously
- Combines post-quantum KEMs with traditional algorithms
- Provides defense in depth against both classical and quantum attacks
- Configurable algorithm selection for each layer

### ⚙️ Customizable Security Levels
- Flexible security modes to balance performance and security
- Perfect Forward Secrecy (PFS) mode with advanced ratcheting
- Best-effort Mode (BEM) for high-performance requirements
- Configurable algorithm combinations per security layer

## ⚡ Threading Modes

The Citadel Protocol provides flexible threading configurations to accommodate different performance requirements and use cases:

### Single-Threaded Mode (Default)
- 🚀 Optimized for low-latency and minimal resource usage
- 📉 Extremely low memory footprint
- ⚡ Rapid message processing with zero thread context switching
- 🎯 Ideal for:
  - Edge devices and IoT applications
  - Real-time communication systems
  - Memory-constrained environments
  - Applications prioritizing consistent low latency

### Multi-Threaded Mode
- 🔄 Parallel processing for high-throughput scenarios
- 🌐 Enhanced scalability for concurrent connections
- 💪 Optimal CPU utilization across multiple cores
- 🎯 Perfect for:
  - Server applications handling numerous concurrent clients
  - High-traffic network services
  - CPU-intensive processing tasks
  - Systems requiring maximum throughput

Enable multi-threaded mode by setting the appropriate feature flag:

```toml
[dependencies]
citadel_sdk = { version = "latest_version", features = ["multi-threaded"] }
```

## 📂 Remote Encrypted Virtual Filesystem

The Remote Encrypted Virtual Filesystem (RE-VFS) is a unique feature that enables secure remote data storage with unprecedented security guarantees:

### 🌟 Key Features
- Store encrypted data on any remote node (peer or server)
- Physical separation of data and decryption keys
- Requires compromising both storage location and client for data access
- Perfect for distributed secure storage solutions

### 🔒 Security Architecture
- Data is encrypted locally using Kyber public key encryption
- Decryption key is never stored with the data
- Uses Kyber scramcryption for minimal ciphertext size
- Optional multiple encryption layers for enhanced security

### 🎯 Use Cases
- Secure cloud storage alternatives
- Distributed backup systems
- P2P file sharing with enhanced security
- Secure document management systems

### 💻 Example Usage
```rust
use citadel_sdk::fs;

async fn store_file(remote: &mut NodeRemote) -> Result<(), Error> {
    // Write file with reinforced security
    fs::write_with_security_level(
        remote,
        "local_file.pdf",
        SecurityLevel::Reinforced,
        "/virtual/path/output.pdf"
    ).await?;

    // Read file back
    let local_path = fs::read(remote, "/virtual/path/output.pdf").await?;
    Ok(())
}
```

## 💾 Backend Storage

The Citadel Protocol offers flexible data persistence options to suit various deployment scenarios:

### 📈 Available Backends
- **🔒 In-Memory Storage**:
  - Fastest performance
  - Perfect for temporary sessions
  - Ideal for testing and development

- **💻 Filesystem Backend** (default):
  - Persistent storage using local filesystem
  - Automatic file management
  - Suitable for single-node deployments

- **📈 SQL Databases**:
  - MySQL: Enterprise-grade reliability
  - PostgreSQL: Advanced features and scalability
  - SQLite: Embedded database option

- **📈 Redis Backend**:
  - High-performance caching
  - Distributed deployment support
  - Perfect for session management

### 📊 Features
- Seamless switching between backends
- Automatic data serialization/deserialization
- Concurrent access support
- Transaction support (where applicable)
- Built-in connection pooling

## 📚 Documentation

- [📖 SDK Documentation](https://avarok-cybersecurity.github.io/Citadel-Protocol/docs/)
- [📚 API Reference](https://docs.rs/citadel_sdk)
- [📁 Examples](./example-library/README.md)
- [📄 Technical Architecture](The_Citadel_Protocol.pdf)

## 📜 Patent and Open Source Commitment

Status: Allowed as of December 2024

The Citadel Protocol's core technology is a [patent-pending innovative security architecture](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/20230403261) that combines multiple novel features into a unique, highly secure communication system. Despite the patent protection, we remain committed to keeping this technology free and open source for the benefit of the entire community. This approach ensures that:

- The protocol remains freely available for everyone to use
- The patent serves to protect the technology from being closed-source or restricted
- Innovation and security improvements can continue to be community-driven
- The core technology stays accessible while being legally protected from potential abuse

## 🧪 Testing

The project includes comprehensive test suites. Use `cargo-make` for running tests:

```bash
# Install cargo-make
cargo install --force cargo-make

# Run local tests
cargo make test-local

# Run comprehensive tests (requires SQL/Redis setup)
cargo make test
```

## 🛡️ Security Considerations

While the Citadel Protocol implements cutting-edge security features:

- The project is pending third-party security audits
- Core cryptographic primitives come from verified [Open Quantum Safe (OQS)](https://openquantumsafe.org/) and [PQClean](https://github.com/PQClean/PQClean) projects
- For maximum security, consider using hybrid cryptography with TLS/QUIC as underlying protocols

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

Please ensure your code:
- Follows Rust best practices
- Includes appropriate tests
- Is properly documented
- Passes all CI checks

## ⚖️ License

This project is dual-licensed for maximum permissibility under:
- [MIT License](LICENSE-MIT)
- [Apache License 2.0](LICENSE-APACHE)

## 📞 Contact

- [🌐 Website](https://avarok.net)
- [💬 Slack Community](https://avarokcybersecurity.slack.com)
- [📝 GitHub Issues](https://github.com/Avarok-Cybersecurity/Citadel-Protocol/issues)

## 👥 Maintainers

- [👨‍💻 Thomas Braun](https://thomaspbraun.com) - Inventor and Core Developer
- [👨‍💻 Donovan Tjemmes](https://github.com/Tjemmmic) - Developer