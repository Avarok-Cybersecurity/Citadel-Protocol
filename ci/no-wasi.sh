#!/usr/bin/env bash
# Fails if WASI support comes back. The browser target is wasm32-unknown-unknown only, and it runs the
# same crates.io tokio as native; the WasmEdge forks of tokio/tokio-util/tokio-stream/socket2 and every
# `target_os = "wasi"` path were removed so there is one runtime implementation to test.
#
# Three checks:
#   1. the wasm32-unknown-unknown graph of the whole workspace holds no WASI crate and no fork source;
#   2. that graph holds exactly one tokio, from crates.io;
#   3. no tracked file reintroduces a WASI cfg, target, feature or fork.
set -euo pipefail

TARGET="wasm32-unknown-unknown"
BANNED_CRATES='^(wasi|wasip1|wasip2|wasix|wasmedge_wasi_socket|wasmedge-wasi-socket|ring-wasi|reqwest_wasi|pqcrypto-falcon-wasi|pqcrypto-traits-wasi)$'
BANNED_SOURCES='second-state/|wasix-org/|ring-wasi'
# `tokio_unstable` and `wasmedge` were set only for the WASI targets.
BANNED_TEXT='target_os *= *"wasi"|wasm32-wasi|second-state|wasix|wasmedge|socket2_wasm|tokio_unstable|wasi-sysroot'
# `.error-logs/` are captured CI logs, not build inputs; this script names the patterns it bans.
SOURCE_EXCLUDES=(':!.error-logs' ':!ci/no-wasi.sh')

fail=0

# `--color never`: CI sets CARGO_TERM_COLOR=always, which wraps cargo tree's repeat marker `(*)` in
# ANSI codes, so the strip below missed it and a repeated tokio read as a second, non-crates.io one.
graph="$(cargo tree --locked --color never --workspace --target "$TARGET" --edges normal,build,dev --prefix none --format '{p}' | sed 's/ (\*)$//' | sort -u)"
if [ -z "$graph" ]; then
    echo "cargo tree printed no crates for $TARGET; refusing to pass an empty graph" >&2
    exit 2
fi

wasi_crates="$(printf '%s\n' "$graph" | awk '{print $1}' | sort -u | grep -E "$BANNED_CRATES" || true)"
if [ -n "$wasi_crates" ]; then
    echo "WASI crates in the $TARGET graph:" >&2
    printf '  %s\n' $wasi_crates >&2
    fail=1
fi

fork_sources="$(printf '%s\n' "$graph" | grep -E "$BANNED_SOURCES" || true)"
if [ -n "$fork_sources" ]; then
    echo "WASI fork sources in the $TARGET graph:" >&2
    printf '  %s\n' "$fork_sources" >&2
    fail=1
fi

tokios="$(printf '%s\n' "$graph" | grep -E '^tokio v' || true)"
if [ "$(printf '%s\n' "$tokios" | grep -c .)" -ne 1 ] || printf '%s\n' "$tokios" | grep -q '('; then
    echo "Expected exactly one crates.io tokio in the $TARGET graph, found:" >&2
    printf '  %s\n' "${tokios:-<none>}" >&2
    fail=1
fi

text_hits="$(git grep -n -I -E "$BANNED_TEXT" -- . "${SOURCE_EXCLUDES[@]}" || true)"
manifest_features="$(git grep -n -E '^[[:space:]]*wasi[[:space:]]*=' -- '*Cargo.toml' || true)"
if [ -n "$text_hits$manifest_features" ]; then
    echo "WASI cfgs, targets, features or forks in tracked files:" >&2
    printf '%s\n' "$text_hits" "$manifest_features" | grep . >&2
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "No WASI crate, fork or cfg; one crates.io tokio on $TARGET ($tokios; $(printf '%s\n' "$graph" | wc -l | tr -d ' ') packages checked)."
