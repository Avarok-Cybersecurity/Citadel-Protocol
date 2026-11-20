#!/usr/bin/env python3
"""Fails when the root Cargo.toml declares a workspace dependency no member uses.

An entry in [workspace.dependencies] that no member inherits pins nothing and reviews nothing,
but it reads as part of the dependency surface. Cargo 1.100 warns about such entries, and a
warning does not fail a build. This makes it fail: every key there must be inherited
(`workspace = true`) by at least one member, in [dependencies], [dev-dependencies],
[build-dependencies] or any [target.*] section of those.

Usage: workspace_deps_gate.py <repo root>
"""
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")


def inherited(manifest: dict) -> set[str]:
    tables = [manifest.get(s, {}) for s in SECTIONS]
    for target in manifest.get("target", {}).values():
        tables.extend(target.get(s, {}) for s in SECTIONS)
    return {
        name
        for table in tables
        for name, spec in table.items()
        if isinstance(spec, dict) and spec.get("workspace") is True
    }


def findings(root: Path) -> list[str]:
    workspace = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]
    declared = set(workspace.get("dependencies", {}))
    used: set[str] = set()
    for member in workspace["members"]:
        used |= inherited(tomllib.loads((root / member / "Cargo.toml").read_text()))
    return [
        f"Cargo.toml: workspace dependency `{name}` is used by no member; remove it"
        for name in sorted(declared - used)
    ]


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    found = findings(Path(sys.argv[1]))
    for line in found:
        print(line)
    if found:
        return 1
    print("every workspace dependency is used by a member")
    return 0


if __name__ == "__main__":
    sys.exit(main())
