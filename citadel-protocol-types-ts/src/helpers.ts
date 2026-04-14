// Runtime helpers for enum types: variant iteration and defaults.
// These supplement the ts-rs generated type definitions with runtime utilities.

import type { ConnectMode } from './ConnectMode';
import type { EncryptionAlgorithm } from './EncryptionAlgorithm';
import type { GroupMemberAlterMode } from './GroupMemberAlterMode';
import type { GroupType } from './GroupType';
import type { HeaderObfuscatorSettings } from './HeaderObfuscatorSettings';
import type { KemAlgorithm } from './KemAlgorithm';
import type { SecrecyMode } from './SecrecyMode';
import type { SecurityLevel } from './SecurityLevel';
import type { SigAlgorithm } from './SigAlgorithm';
import type { UdpMode } from './UdpMode';

// --- UdpMode ---

export function allUdpModeValues(): UdpMode[] {
  return ['Disabled', 'Enabled'];
}

export function defaultUdpMode(): UdpMode {
  return 'Disabled';
}

// --- EncryptionAlgorithm ---

export function allEncryptionAlgorithmValues(): EncryptionAlgorithm[] {
  return ['AES_GCM_256', 'ChaCha20Poly_1305', 'MlKemHybrid', 'Ascon80pq'];
}

export function defaultEncryptionAlgorithm(): EncryptionAlgorithm {
  return 'AES_GCM_256';
}

// --- SecrecyMode ---

export function allSecrecyModeValues(): SecrecyMode[] {
  return ['BestEffort', 'Perfect'];
}

export function defaultSecrecyMode(): SecrecyMode {
  return 'BestEffort';
}

// --- KemAlgorithm ---

export function allKemAlgorithmValues(): KemAlgorithm[] {
  return ['MlKem'];
}

export function defaultKemAlgorithm(): KemAlgorithm {
  return 'MlKem';
}

// --- SigAlgorithm ---

export function allSigAlgorithmValues(): SigAlgorithm[] {
  return ['None', 'MlDsa65', 'FnDsa512'];
}

export function defaultSigAlgorithm(): SigAlgorithm {
  return 'None';
}

// --- GroupType ---

export function allGroupTypeValues(): GroupType[] {
  return ['Public', 'Private'];
}

// --- GroupMemberAlterMode ---

export function allGroupMemberAlterModeValues(): GroupMemberAlterMode[] {
  return ['Leave', 'Kick'];
}

// --- SecurityLevel ---
// Note: SecurityLevel also supports { Custom: number } which is not included
// in allValues since it requires a parameter.

export function allSecurityLevelValues(): SecurityLevel[] {
  return ['Standard', 'Reinforced', 'High', 'Ultra', 'Extreme'];
}

export function defaultSecurityLevel(): SecurityLevel {
  return 'Standard';
}

// --- HeaderObfuscatorSettings ---
// Note: HeaderObfuscatorSettings also supports { EnabledWithKey: bigint }
// which is not included in allValues since it requires a parameter.

export function allHeaderObfuscatorSettingsValues(): HeaderObfuscatorSettings[] {
  return ['Disabled', 'Enabled'];
}

export function defaultHeaderObfuscatorSettings(): HeaderObfuscatorSettings {
  return 'Disabled';
}

// --- ConnectMode ---

export function defaultConnectMode(): ConnectMode {
  return { Standard: { force_login: false } };
}
