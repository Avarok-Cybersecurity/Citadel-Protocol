#!/usr/bin/env python3
"""Fails unless every import of each given wasm32-unknown-unknown module comes from wasm-bindgen.

A raw cargo artifact links its host functions through `__wbindgen_*` modules only. Any other import
module (`wasi_snapshot_preview1`, `wasi:*`, `env`, ...) means a dependency expects a host the browser
does not provide. Usage: wasm-imports-are-bindgen-only.py FILE.wasm...
"""
import sys
from collections import Counter

ALLOWED_PREFIX = "__wbindgen_"
IMPORT_SECTION = 2


def leb(buf, i):
    result = shift = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            return result, i
        shift += 7


def skip_limits(buf, i):
    flags = buf[i]
    _, i = leb(buf, i + 1)
    if flags & 1:
        _, i = leb(buf, i)
    return i


def import_modules(buf):
    if buf[:4] != b"\0asm":
        raise SystemExit("not a wasm binary")
    i = 8
    modules = []
    while i < len(buf):
        section = buf[i]
        size, i = leb(buf, i + 1)
        end = i + size
        if section == IMPORT_SECTION:
            count, i = leb(buf, i)
            for _ in range(count):
                length, i = leb(buf, i)
                module = buf[i:i + length].decode()
                length, i = leb(buf, i + length)
                i += length
                kind = buf[i]
                i += 1
                if kind == 0:  # function: type index
                    _, i = leb(buf, i)
                elif kind == 1:  # table: reftype + limits
                    i = skip_limits(buf, i + 1)
                elif kind == 2:  # memory: limits
                    i = skip_limits(buf, i)
                elif kind == 3:  # global: valtype + mutability
                    i += 2
                else:
                    raise SystemExit(f"unknown import kind {kind}")
                modules.append(module)
        i = end
    return modules


def main(paths):
    if not paths:
        raise SystemExit("no wasm files given; refusing to pass an empty set")
    failed = False
    for path in paths:
        with open(path, "rb") as f:
            modules = Counter(import_modules(f.read()))
        foreign = {m: n for m, n in modules.items() if not m.startswith(ALLOWED_PREFIX)}
        print(f"{path}: {sum(modules.values())} imports, modules {dict(modules)}")
        if not modules:
            print(f"  no imports at all; this is not a wasm-bindgen artifact", file=sys.stderr)
            failed = True
        if foreign:
            print(f"  imports from outside wasm-bindgen: {foreign}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
