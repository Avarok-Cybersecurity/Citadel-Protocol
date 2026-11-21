#!/usr/bin/env python3
"""Fails when a pull request would put an internal tracking identifier into public history.

Internal work is tracked under short identifiers that mean nothing outside the team and do not
belong in this repository's public history. This reads the message of every commit the pull
request adds (merge-base..HEAD, so commits already on the base branch are never judged) and the
pull request's title and body, passed in through PR_TITLE and PR_BODY, and names each line that
carries one.

Usage: tracking_id_gate.py <repo root> <base ref>
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

# A letter or dash before the prefix marks a longer, public name (a signature scheme such as
# ML-DSA-65), which is not a tracking identifier.
PATTERNS = [
    re.compile(r"\b(?<![A-Za-z-])SA-[0-9]+\b", re.IGNORECASE),
    re.compile(r"\bGHSA-[0-9a-z]{4}-", re.IGNORECASE),
]
RECORD = "\x1e"
FIELD = "\x00"


def scan(text: str) -> list[tuple[int, str]]:
    """The 1-based number and text of each line carrying a tracking identifier."""
    return [
        (n, line)
        for n, line in enumerate(text.splitlines(), 1)
        if any(p.search(line) for p in PATTERNS)
    ]


def findings(sources: list[tuple[str, str]]) -> list[str]:
    """One message per offending line, for (where, text) pairs."""
    return [f"{where} line {n}: {line.strip()}" for where, text in sources for n, line in scan(text)]


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout


def commit_messages(root: Path, base_ref: str) -> list[tuple[str, str]]:
    merge_base = git(root, "merge-base", "HEAD", base_ref).strip()
    log = git(root, "log", "--format=%H%x00%B%x1e", f"{merge_base}..HEAD")
    out = []
    for record in log.split(RECORD):
        if FIELD in record:
            sha, body = record.split(FIELD, 1)
            out.append((f"commit {sha.strip()[:12]}", body))
    return out


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    sources = commit_messages(Path(sys.argv[1]), sys.argv[2])
    sources += [(f"pull request {name.lower()}", os.environ[f"PR_{name}"])
                for name in ("TITLE", "BODY") if f"PR_{name}" in os.environ]
    found = findings(sources)
    for line in found:
        print(f"tracking_id_gate: {line}", file=sys.stderr)
    if found:
        print("tracking_id_gate: keep internal tracking identifiers out of public history; "
              "reword the commit message (or the pull request text) without them", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
