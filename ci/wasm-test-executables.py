#!/usr/bin/env python3
"""Prints the test executable cargo built for each named test target, one path per line.

Cargo decides where a test binary lands (the build-dir layout moved it from `deps/` to
`build/<pkg>/<hash>/out/`), so a hard-coded path or glob goes stale silently. This reads the
`compiler-artifact` messages of `cargo test --no-run --message-format=json` instead, and fails
unless every named target produced exactly one existing executable.
Usage: wasm-test-executables.py CARGO_JSON_FILE TEST_NAME...
"""
import json
import os
import sys


def executables_by_test(lines):
    found = {}
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        message = json.loads(line)
        if message.get("reason") != "compiler-artifact" or not message.get("profile", {}).get("test"):
            continue
        executable = message.get("executable")
        if executable:
            found.setdefault(message["target"]["name"], set()).add(executable)
    return found


def main(argv):
    if len(argv) < 2:
        raise SystemExit("usage: wasm-test-executables.py CARGO_JSON_FILE TEST_NAME...")
    with open(argv[0], encoding="utf-8") as f:
        found = executables_by_test(f)
    paths = []
    for name in argv[1:]:
        candidates = sorted(found.get(name, ()))
        if len(candidates) != 1:
            raise SystemExit(f"test target {name!r}: expected exactly one executable, cargo reported {candidates}")
        if not os.path.isfile(candidates[0]):
            raise SystemExit(f"test target {name!r}: cargo reported {candidates[0]}, which does not exist")
        paths.append(candidates[0])
    print("\n".join(paths))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
