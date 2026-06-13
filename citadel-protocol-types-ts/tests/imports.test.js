const { test, describe } = require('node:test');
const assert = require('node:assert');

describe('Citadel Protocol Types', () => {
  test('can import types module', async () => {
    const types = await import('../dist/index.js');
    assert.ok(types);
  });

  test('protocol_version returns valid semver', async () => {
    const { protocol_version } = await import('../dist/index.js');
    const version = protocol_version();
    assert.ok(typeof version === 'string', 'protocol_version should return a string');
    assert.match(version, /^\d+\.\d+\.\d+$/, 'version should match semver format');
  });

  test('sdk_version returns valid semver', async () => {
    const { sdk_version } = await import('../dist/index.js');
    const version = sdk_version();
    assert.ok(typeof version === 'string', 'sdk_version should return a string');
    assert.match(version, /^\d+\.\d+\.\d+$/, 'version should match semver format');
  });

  test('protocol and SDK versions are consistent', async () => {
    const { protocol_version, sdk_version } = await import('../dist/index.js');
    const pv = protocol_version();
    const sv = sdk_version();

    // Both should be valid versions
    assert.ok(pv.split('.').length === 3, 'protocol version should have 3 parts');
    assert.ok(sv.split('.').length === 3, 'SDK version should have 3 parts');

    // Protocol version should be 0.10.0 based on constants.rs (bumped 9 -> 10 for the BLAKE3
    // nonce-KDF wire change).
    assert.strictEqual(pv, '0.10.0', 'protocol version should match expected');
  });
});

describe('Enum Helpers', () => {
  test('allUdpModeValues returns all variants', async () => {
    const { allUdpModeValues, defaultUdpMode } = await import('../dist/index.js');
    const values = allUdpModeValues();
    assert.strictEqual(values.length, 2);
    assert.ok(values.includes('Disabled'));
    assert.ok(values.includes('Enabled'));
    assert.ok(values.includes(defaultUdpMode()));
  });

  test('allEncryptionAlgorithmValues returns all variants', async () => {
    const { allEncryptionAlgorithmValues, defaultEncryptionAlgorithm } = await import('../dist/index.js');
    const values = allEncryptionAlgorithmValues();
    assert.strictEqual(values.length, 4);
    assert.ok(values.includes('AES_GCM_256'));
    assert.ok(values.includes('ChaCha20Poly_1305'));
    assert.ok(values.includes('MlKemHybrid'));
    assert.ok(values.includes('Ascon80pq'));
    assert.ok(values.includes(defaultEncryptionAlgorithm()));
  });

  test('allSecrecyModeValues returns all variants', async () => {
    const { allSecrecyModeValues, defaultSecrecyMode } = await import('../dist/index.js');
    const values = allSecrecyModeValues();
    assert.strictEqual(values.length, 2);
    assert.ok(values.includes('BestEffort'));
    assert.ok(values.includes('Perfect'));
    assert.ok(values.includes(defaultSecrecyMode()));
  });

  test('allKemAlgorithmValues returns all variants', async () => {
    const { allKemAlgorithmValues, defaultKemAlgorithm } = await import('../dist/index.js');
    const values = allKemAlgorithmValues();
    assert.strictEqual(values.length, 1);
    assert.ok(values.includes('MlKem'));
    assert.ok(values.includes(defaultKemAlgorithm()));
  });

  test('allSigAlgorithmValues returns all variants', async () => {
    const { allSigAlgorithmValues, defaultSigAlgorithm } = await import('../dist/index.js');
    const values = allSigAlgorithmValues();
    assert.strictEqual(values.length, 3);
    assert.ok(values.includes('None'));
    assert.ok(values.includes('MlDsa65'));
    assert.ok(values.includes('FnDsa512'));
    assert.ok(values.includes(defaultSigAlgorithm()));
  });

  test('allGroupTypeValues returns all variants', async () => {
    const { allGroupTypeValues } = await import('../dist/index.js');
    const values = allGroupTypeValues();
    assert.strictEqual(values.length, 2);
    assert.ok(values.includes('Public'));
    assert.ok(values.includes('Private'));
  });

  test('allGroupMemberAlterModeValues returns all variants', async () => {
    const { allGroupMemberAlterModeValues } = await import('../dist/index.js');
    const values = allGroupMemberAlterModeValues();
    assert.strictEqual(values.length, 2);
    assert.ok(values.includes('Leave'));
    assert.ok(values.includes('Kick'));
  });

  test('allSecurityLevelValues returns string-literal variants', async () => {
    const { allSecurityLevelValues, defaultSecurityLevel } = await import('../dist/index.js');
    const values = allSecurityLevelValues();
    assert.strictEqual(values.length, 5);
    assert.ok(values.includes('Standard'));
    assert.ok(values.includes('Reinforced'));
    assert.ok(values.includes('High'));
    assert.ok(values.includes('Ultra'));
    assert.ok(values.includes('Extreme'));
    assert.ok(values.includes(defaultSecurityLevel()));
  });

  test('allHeaderObfuscatorSettingsValues returns string-literal variants', async () => {
    const { allHeaderObfuscatorSettingsValues, defaultHeaderObfuscatorSettings } = await import('../dist/index.js');
    const values = allHeaderObfuscatorSettingsValues();
    assert.strictEqual(values.length, 2);
    assert.ok(values.includes('Disabled'));
    assert.ok(values.includes('Enabled'));
    assert.ok(values.includes(defaultHeaderObfuscatorSettings()));
  });

  test('defaultConnectMode returns Standard with force_login false', async () => {
    const { defaultConnectMode } = await import('../dist/index.js');
    const mode = defaultConnectMode();
    assert.deepStrictEqual(mode, { Standard: { force_login: false } });
  });
});
