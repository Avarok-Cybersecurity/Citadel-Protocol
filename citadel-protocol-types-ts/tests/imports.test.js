const { test, describe } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const CONSTANTS_PATH = path.join(__dirname, '../../citadel_proto/src/constants.rs');

/**
 * Reads `pub const <name>: u8 = <n>;` from citadel_proto's constants.rs, the source of the
 * protocol version. Read here independently of scripts/inject-versions.js, so the test checks
 * what the build injected against the source rather than against the injector itself.
 */
function u8Constant(source, name) {
  const match = source.match(new RegExp(`pub const ${name}:\\s*u8\\s*=\\s*(\\d+);`));
  if (!match) {
    throw new Error(`${name} not found in ${CONSTANTS_PATH}`);
  }
  return match[1];
}

function protocolVersionFromConstants() {
  const source = fs.readFileSync(CONSTANTS_PATH, 'utf-8');
  return ['MAJOR_VERSION', 'MINOR_VERSION', 'PATCH_VERSION']
    .map((name) => u8Constant(source, name))
    .join('.');
}

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

    assert.strictEqual(pv, protocolVersionFromConstants(), 'protocol version should match constants.rs');
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
    assert.strictEqual(values.length, 2);
    assert.ok(values.includes('MlKem768Fips203'));
    assert.ok(values.includes('MlKem1024Fips203'));
    assert.ok(!values.includes('MlKem'));
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
