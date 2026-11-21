#!/usr/bin/env bash
# Clippy for wasm32-unknown-unknown, warnings denied, over every feature set the browser build uses.
#
# Without `--no-deps`, clippy lints every workspace crate in the graph, so linting citadel_sdk (or
# citadel_media) also lints citadel_proto, citadel_user, citadel_crypt and the rest under exactly
# the features that configuration enables. Each line below is one such configuration:
#   1. the default build of every crate that targets the browser;
#   2. citadel_pqcrypto without default features, as wasm_check's `cargo check` builds it;
#   3. citadel_sdk without default features, with every wasm test target wasm-pack runs;
#   4. the browser security-key backend and its test;
#   5. citadel_media with its wasm test;
# then a build of the browser SDK, for the lints only a build runs (see below).
# A wasm-only warning (an import or item that only native code uses) fails here and nowhere else.
set -euo pipefail

TARGET=wasm32-unknown-unknown
# Every wasm test target in citadel_sdk, from the tree, so a new one cannot be left unlinted.
mapfile -t sdk_wasm_tests < <(cd citadel_sdk/tests && ls wasm_*.rs | sed 's/\.rs$//' | grep -v '^wasm_security_key$')
if [ "${#sdk_wasm_tests[@]}" -eq 0 ]; then
    echo "found no citadel_sdk/tests/wasm_*.rs; refusing to lint nothing" >&2
    exit 2
fi
sdk_test_args=()
for t in "${sdk_wasm_tests[@]}"; do sdk_test_args+=(--test "$t"); done

clippy() {
    echo "::group::cargo clippy --target $TARGET $*"
    cargo clippy --locked --target "$TARGET" "$@" -- -D warnings
    echo "::endgroup::"
}

clippy -p citadel_sdk -p citadel_media -p citadel_wire -p netbeam -p async_ip -p citadel_treekem -p citadel_logging -p citadel_link -p citadel_negotiation
clippy -p citadel_pqcrypto --no-default-features
clippy -p citadel_sdk --no-default-features --lib "${sdk_test_args[@]}"
clippy -p citadel_sdk --no-default-features --features security-key --lib --test wasm_security_key
clippy -p citadel_media --lib --test wasm_media

# rustc's deny-by-default lints that need the optimised MIR (arithmetic_overflow, unconditional
# panics) run only when code is built, not under clippy or `cargo check`. A value that overflows a
# 32-bit usize compiles natively and fails only here, so the browser SDK is also built.
echo "::group::cargo build --target $TARGET -p citadel_sdk --no-default-features --lib"
cargo build --locked --target "$TARGET" -p citadel_sdk --no-default-features --lib
echo "::endgroup::"
