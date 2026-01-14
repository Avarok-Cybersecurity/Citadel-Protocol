# @avarok/citadel-protocol-types

[![npm version](https://badge.fury.io/js/%40avarok%2Fcitadel-protocol-types.svg)](https://www.npmjs.com/package/@avarok/citadel-protocol-types)

TypeScript type definitions for the Citadel Protocol, automatically generated from Rust types.

## Installation

```bash
npm install @avarok/citadel-protocol-types
```

## Version Functions

Get the protocol and SDK versions programmatically:

```typescript
import { protocol_version, sdk_version } from '@avarok/citadel-protocol-types';

console.log(`Protocol version: ${protocol_version()}`);  // e.g., "0.9.0"
console.log(`SDK version: ${sdk_version()}`);            // e.g., "0.13.0"
```

## Usage

```typescript
import {
  ConnectMode,
  SecurityLevel,
  UserIdentifier,
  MutualPeer,
  CryptoParameters,
  ClientConnectionType,
  PeerConnectionType,
  VirtualConnectionType,
  Error as CitadelError
} from '@avarok/citadel-protocol-types';

// Use the types in your TypeScript code
const peer: MutualPeer = {
  parent_icid: 12345n,
  cid: 67890n,
  username: "alice"
};

const securityLevel: SecurityLevel = "High";

// Connection types for C2S and P2P connections
const c2sConnection: ClientConnectionType = {
  Server: { session_cid: 12345n }
};

const p2pConnection: PeerConnectionType = {
  LocalGroupPeer: { session_cid: 12345n, peer_cid: 67890n }
};
```

## Available Types

### Version Functions
- `protocol_version()` - Returns the Citadel Protocol version
- `sdk_version()` - Returns the Citadel SDK version

### User Types
- `MutualPeer`
- `PeerInfo`
- `UserIdentifier`

### Connection Types
- `ClientConnectionType` - C2S connection variants (Server, Extended)
- `PeerConnectionType` - P2P connection variants (LocalGroupPeer, ExternalGroupPeer)
- `VirtualConnectionType` - Unified connection type for routing

### Protocol Types
- `ConnectMode`
- `VirtualObjectMetadata`
- `ObjectId`
- `ObjectTransferOrientation`
- `ObjectTransferStatus`
- `SessionSecuritySettings`
- `UdpMode`
- `MemberState`
- `GroupMemberAlterMode`
- `MessageGroupOptions`
- `GroupType`
- `MessageGroupKey`
- `TransferType`

### Crypto Types
- `CryptoParameters`
- `EncryptionAlgorithm`
- `SecrecyMode`
- `KemAlgorithm`
- `SigAlgorithm`
- `SecurityLevel`
- `HeaderObfuscatorSettings`
- `PreSharedKey`

### Error Types
- `Error` - The main error type for the Citadel Protocol

## Regenerating Types

To regenerate the TypeScript types from the Rust source:

```bash
cd ../citadel_types
cargo run --bin export_ts --features typescript
```

Then rebuild the TypeScript library:

```bash
npm run build
```

## Links

- [Citadel Protocol GitHub](https://github.com/Avarok-Cybersecurity/Citadel-Protocol)
- [Avarok Cybersecurity](https://avarok.net/)

## License

MIT OR Apache-2.0
