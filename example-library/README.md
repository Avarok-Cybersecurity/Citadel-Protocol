# Citadel Protocol Examples

This directory contains examples demonstrating how to use the Citadel Protocol for various networking scenarios, including client-server (C2S) and peer-to-peer (P2P) communication patterns.

## Important First Step: Running a Server

**Before running any example, you must have a Citadel server running!**

1. First, set the server address:
```bash
export CITADEL_SERVER_ADDR="127.0.0.1:25000"
```

2. Start a basic server:
```bash
cargo run --example server_basic
```

3. Keep this server running while you try other examples in separate terminals.

## Prerequisites

Additional environment variables needed for specific examples:

```bash
# For P2P examples
export CITADEL_MY_USER="user1"      # Your username
export CITADEL_OTHER_USER="user2"    # Peer's username you want to connect to
```

## Available Examples

### Client-Server (C2S) Examples

1. **Basic Client Examples**
   - `client_basic_transient_connection.rs`: Demonstrates temporary connections without persistent user accounts
   - `client_basic_with_server_password.rs`: Shows how to connect to password-protected servers
   - `client_echo.rs`: A simple echo client demonstrating basic message exchange using a credentialed, persistent account

2. **Server Examples**
   - `server_basic.rs`: A basic Citadel server implementation
   - `server_basic_with_password.rs`: Server with password protection enabled
   - `server_echo.rs`: Echo server implementation responding to client messages

### Peer-to-Peer (P2P) Examples

1. **Chat Application**
   - `chat.rs`: Interactive P2P chat application using standard input/output
   
2. **File Operations**
   - `file_transfer.rs`: Secure file transfer between peers
   
3. **Remote Encrypted Virtual Filesystem (RE-VFS)**
   - `revfs_read_write.rs`: Basic read/write operations using RE-VFS
   - `revfs_delete.rs`: File deletion operations
   - `revfs_take.rs`: Takes a file from the RE-VFS, deleting it from the RE-VFS in the process

## Running the Examples

### For Client-Server Examples:

1. Make sure you have a server running (see "Important First Step" above)

2. Then run a client:
```bash
# Basic client
cargo run --example client_basic_transient_connection

# Or with server password
cargo run --example client_basic_with_server_password
```

### For P2P Examples:

1. Make sure you have a server running (see "Important First Step" above)

2. For the chat example, run two instances:
```bash
# First peer
export CITADEL_MY_USER="user1"
export CITADEL_OTHER_USER="user2"
cargo run --example chat

# Second peer (in another terminal)
export CITADEL_MY_USER="user2"
export CITADEL_OTHER_USER="user1"
cargo run --example chat
```

3. For file transfer:
```bash
# Sender
export CITADEL_MY_USER="sender"
export CITADEL_OTHER_USER="receiver"
cargo run --example file_transfer

# Receiver (in another terminal)
export CITADEL_MY_USER="receiver"
export CITADEL_OTHER_USER="sender"
cargo run --example file_transfer
```

Each example contains detailed documentation at the top of its source file explaining specific usage and features. For more detailed information about each example, see the [examples/README.md](examples/README.md) file.
