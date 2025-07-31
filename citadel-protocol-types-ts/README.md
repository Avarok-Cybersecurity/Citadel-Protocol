# @avarok/citadel-protocol-types

TypeScript type definitions for the Citadel Protocol, automatically generated from Rust types.

## Installation

```bash
npm install @avarok/citadel-protocol-types
```

## Usage

```typescript
import { 
  ConnectMode, 
  SecurityLevel, 
  UserIdentifier,
  MutualPeer, 
  CryptoParameters,
  Error as CitadelError 
} from '@avarok/citadel-protocol-types';

// Use the types in your TypeScript code
const peer: MutualPeer = {
  parent_icid: 12345n,
  cid: 67890n,
  username: "alice"
};

const securityLevel: SecurityLevel = "High";
```

## Available Types

### User Types
- `MutualPeer`
- `PeerInfo`
- `UserIdentifier`

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
