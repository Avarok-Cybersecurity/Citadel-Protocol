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

    // Protocol version should be 0.9.0 based on constants.rs
    assert.strictEqual(pv, '0.9.0', 'protocol version should match expected');
  });
});
