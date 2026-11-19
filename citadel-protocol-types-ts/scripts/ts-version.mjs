#!/usr/bin/env node
// The npm version a types change is published as, derived and never typed.
//
// TYPES-SYNC D1 (owner, 2026-11-19): every change to the generated types is
// released automatically, as a prerelease whose name is the content it holds,
// and consumers pin it exactly. `<next patch of package.json>-t.<8 hex>`, the
// hex being SHA3-256 over src/*.ts by sorted name (`<name>\0<bytes>\0`), so:
//   - the same sources always get the same version (a rerun publishes nothing);
//   - it sorts above the release package.json names, which is already on npm;
//   - `^0.14.x` ranges never float onto it: only an exact pin takes it.
// A deliberate release still goes out as package.json says, unchanged: this is
// only for the changes between them.
//
// Run after `npm run build`, whose prebuild writes src/versions.ts.
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const PKG = join(dirname(fileURLToPath(import.meta.url)), '..');

export function derivedVersion(pkgDir) {
  const { version } = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'));
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  if (!m) throw new Error(`package.json version ${version} is not a plain release, so no prerelease can follow it`);
  const src = join(pkgDir, 'src');
  const names = readdirSync(src).filter((n) => n.endsWith('.ts')).sort();
  if (names.length === 0) throw new Error(`${src} holds no sources`);
  const hash = createHash('sha3-256');
  for (const name of names) {
    hash.update(name);
    hash.update('\0');
    hash.update(readFileSync(join(src, name)));
    hash.update('\0');
  }
  return `${m[1]}.${m[2]}.${Number(m[3]) + 1}-t.${hash.digest('hex').slice(0, 8)}`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) console.log(derivedVersion(PKG));
