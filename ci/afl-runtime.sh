#!/usr/bin/env bash
# cargo-afl, and the AFL++ runtime it links the fuzz/ harnesses against, for the toolchain that
# rust-toolchain.toml pins.
#
# cargo-afl keeps one runtime per rustc version and cargo-afl version, so each toolchain bump
# needs a new one; without it `cargo afl build` stops with "AFL LLVM runtime was not built for
# Rust rustc-...". A prebuilt cargo-afl (cargo binstall) cannot build one: it copies AFL++'s
# sources from the path its crate had on the machine that compiled it. So cargo-afl is installed
# from source, at the version of the afl crate fuzz/Cargo.lock pins (the two must agree).
#
# Usage: ci/afl-runtime.sh check     fails, naming the command to run, unless both are in place
#        ci/afl-runtime.sh install   installs whichever is missing
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
want="$(awk '$0 == "name = \"afl\"" { getline; gsub(/^version = "|"$/, ""); print; exit }' "$root/fuzz/Cargo.lock")"
if [ -z "$want" ]; then
  echo "afl-runtime: fuzz/Cargo.lock pins no afl crate" >&2
  exit 1
fi

installed() { cargo afl --version 2>/dev/null | awk '{ print $2 }' || true; }
toolchain() { rustc -vV | awk '/^release:/ { r = $2 } /^commit-hash:/ { c = substr($2, 1, 7) } END { print "rustc-" r "-" c }'; }
# cargo-afl checks for the runtime before it parses its arguments, so asking for help is enough.
runtime_built() { (cd "$root/fuzz" && cargo afl build --locked --help >/dev/null 2>&1); }

case "${1:-}" in
  check)
    have="$(installed)"
    if [ "$have" != "$want" ]; then
      echo "afl-runtime: cargo-afl ${have:-is not installed}${have:+ is installed}, fuzz/Cargo.lock pins afl $want; run: cargo install cargo-afl --version $want --locked" >&2
      exit 1
    fi
    if ! runtime_built; then
      echo "afl-runtime: no AFL++ runtime for $(toolchain) (rust-toolchain.toml) and cargo-afl $want; run: cargo afl config --build" >&2
      exit 1
    fi
    echo "afl-runtime: cargo-afl $want with its AFL++ runtime for $(toolchain)"
    ;;
  install)
    [ "$(installed)" = "$want" ] || cargo install cargo-afl --version "$want" --locked
    runtime_built || cargo afl config --build
    "$0" check
    ;;
  *)
    echo "usage: $0 check|install" >&2
    exit 2
    ;;
esac
