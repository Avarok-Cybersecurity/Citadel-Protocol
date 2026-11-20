#!/usr/bin/env python3
"""Fails when a build takes its Rust toolchain from anywhere but rust-toolchain.toml.

rust-toolchain.toml names one exact version. A floating toolchain (`@stable`, `toolchain:
stable`, `rustup default stable`, `cargo +nightly`) changes the build, and every CI cache key,
on each Rust release; #391's release legs went cold and timed out that way. This reads every
workflow and local action, and every Dockerfile: an image must install the pinned toolchain
(`rustup toolchain install`, after copying the tree) before it runs cargo.

Usage: toolchain_pin_gate.py <repo root>
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

CHANNEL = re.compile(r"^\d+\.\d+\.\d+$")
FLOATING = [
    re.compile(r"rust-toolchain@(stable|beta|nightly)\b"),
    re.compile(r"\btoolchain:\s*['\"]?(stable|beta|nightly)\b"),
    re.compile(r"\brustup\s+(default|update|toolchain\s+install|override\s+set)\s+(stable|beta|nightly)\b"),
    re.compile(r"\bcargo\s+\+(stable|beta|nightly)\b"),
    re.compile(r"--toolchain[\s=](stable|beta|nightly)\b"),
    re.compile(r"\"--toolchain\",\s*\"(stable|beta|nightly)\""),
]
INSTALL = re.compile(r"\brustup\s+toolchain\s+install\s*(&&|$|\\)", re.M)
CARGO = re.compile(r"\b(cargo|wasm-pack)\s")


def pinned_channel_problem(toolchain_toml: str) -> str | None:
    channel = tomllib.loads(toolchain_toml).get("toolchain", {}).get("channel")
    if channel is None or not CHANNEL.match(channel):
        return f"rust-toolchain.toml must name an exact version (x.y.z), not {channel!r}"
    return None


def floating_uses(text: str) -> list[str]:
    return [m.group(0) for pattern in FLOATING for m in pattern.finditer(text)]


def dockerfile_problem(text: str) -> str | None:
    """An image that runs cargo must install the pinned toolchain after copying the tree."""
    copy = re.search(r"^COPY\s+\.\s+\.", text, re.M)
    run_lines = [(m.start(), m.group(0)) for m in re.finditer(r"^RUN .*$", text, re.M)]
    first_cargo = next((at for at, line in run_lines if CARGO.search(line)), None)
    if first_cargo is None:
        return None
    install = next((at for at, line in run_lines if INSTALL.search(line[4:])), None)
    if install is None or copy is None or not (copy.start() < install < first_cargo):
        return "runs cargo without `RUN rustup toolchain install` between `COPY . .` and it"
    return None


def findings(root: Path) -> list[str]:
    out = []
    toolchain = root / "rust-toolchain.toml"
    if not toolchain.exists():
        out.append("rust-toolchain.toml is missing")
    elif problem := pinned_channel_problem(toolchain.read_text()):
        out.append(problem)
    for path in sorted((root / ".github").rglob("*.y*ml")) + [root / "Makefile.toml"]:
        if path.exists():
            out += [f"{path.relative_to(root)}: floats its toolchain: {use}" for use in floating_uses(path.read_text())]
    for path in sorted(root.glob("docker/**/Dockerfile*")):
        if problem := dockerfile_problem(path.read_text()):
            out.append(f"{path.relative_to(root)}: {problem}")
    return out


def main() -> int:
    found = findings(Path(sys.argv[1]))
    for line in found:
        print(f"toolchain_pin_gate: {line}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
