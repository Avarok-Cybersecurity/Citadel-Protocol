// The derived prerelease version (scripts/ts-version.mjs) is a function of the
// sources: equal sources, equal version; any change, a new one; and it always
// follows the release package.json names.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { derivedVersion } from '../scripts/ts-version.mjs';

function pkg(version) {
  const dir = mkdtempSync(join(tmpdir(), 'ts-version-'));
  mkdirSync(join(dir, 'src'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ version }));
  writeFileSync(join(dir, 'src', 'A.ts'), 'export type A = "x";\n');
  return dir;
}

test('the same sources give the same version, after the release', () => {
  const v = derivedVersion(pkg('0.14.1'));
  assert.match(v, /^0\.14\.2-t\.[0-9a-f]{8}$/);
  assert.equal(derivedVersion(pkg('0.14.1')), v);
});

test('a change to any source is a new version', () => {
  const dir = pkg('0.14.1');
  const before = derivedVersion(dir);
  appendFileSync(join(dir, 'src', 'A.ts'), 'export type B = "y";\n');
  assert.notEqual(derivedVersion(dir), before);
});

test('a prerelease base is refused rather than stacked', () => {
  assert.throws(() => derivedVersion(pkg('0.14.2-t.deadbeef')), /not a plain release/);
});
