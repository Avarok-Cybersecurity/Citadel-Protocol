#!/usr/bin/env python3
"""Fails when the TypeScript types change but @avarok/citadel-protocol-types keeps its version.

The npm package publishes on a master push that touches its bindings or the Rust types they are
generated from, but only when package.json names a version npm does not have yet; otherwise the
publish job skips. #391 changed `KemAlgorithm` and left the version at one npm already had, so
master carried the new types and npm never did. This compares the branch with its merge-base on
the base branch: if any watched path changed, package.json and package-lock.json must both name
a version greater than the merge-base's.

Usage: types_version_gate.py <repo root> <base ref, e.g. origin/master>
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

PACKAGE_DIR = "citadel-protocol-types-ts"
WATCHED = (f"{PACKAGE_DIR}/src/", "citadel_types/src/")
SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def parse_version(version: str) -> tuple[int, int, int]:
    match = SEMVER.match(version)
    if match is None:
        raise ValueError(f"not a plain x.y.z version: {version!r}")
    return int(match[1]), int(match[2]), int(match[3])


def watched_changes(changed_paths: list[str]) -> list[str]:
    return [path for path in changed_paths if path.startswith(WATCHED)]


def problems(changed_paths: list[str], base_version: str, head_version: str, lock_version: str) -> list[str]:
    out = []
    if lock_version != head_version:
        out.append(f"{PACKAGE_DIR}/package-lock.json names {lock_version}, package.json names {head_version}")
    touched = watched_changes(changed_paths)
    if touched and parse_version(head_version) <= parse_version(base_version):
        out.append(
            f"{len(touched)} types path(s) changed (first: {touched[0]}) but the package version is "
            f"{head_version}, not above the merge-base's {base_version}; npm would skip the publish"
        )
    return out


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout


def package_version(text: str) -> str:
    return json.loads(text)["version"]


def findings(root: Path, base_ref: str) -> list[str]:
    merge_base = git(root, "merge-base", "HEAD", base_ref).strip()
    changed = git(root, "diff", "--name-only", merge_base, "HEAD").splitlines()
    base_version = package_version(git(root, "show", f"{merge_base}:{PACKAGE_DIR}/package.json"))
    head_version = package_version((root / PACKAGE_DIR / "package.json").read_text())
    lock_version = package_version((root / PACKAGE_DIR / "package-lock.json").read_text())
    return problems(changed, base_version, head_version, lock_version)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    found = findings(Path(sys.argv[1]), sys.argv[2])
    for line in found:
        print(f"types_version_gate: {line}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
