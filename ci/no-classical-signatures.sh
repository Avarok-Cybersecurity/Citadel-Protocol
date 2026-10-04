#!/usr/bin/env bash
# Fails if a classical signature implementation is in the build graph of the server a tenant's
# Durable Object compiles: citadel_sdk for wasm32-unknown-unknown, normal (non-dev) dependencies.
#
# Sign-in is post-quantum only (ML-KEM factors, see citadel_user::auth::pq): nothing may verify
# an ECDSA, Ed25519 or RSA signature, so none of the crates that do can be linked. `ring` and
# `webauthn-rs` are listed because each brings them in.
set -euo pipefail

BANNED='^(p256|p384|p521|ecdsa|ed25519|ed25519-dalek|ed25519-compact|rsa|ring|webauthn-rs|webauthn-rs-core|k256)$'
TARGET="${TARGET:-wasm32-unknown-unknown}"
PACKAGE="${PACKAGE:-citadel_sdk}"

graph="$(cargo tree --package "$PACKAGE" --target "$TARGET" --edges normal --prefix none --format '{p}')"
crates="$(printf '%s\n' "$graph" | awk '{print $1}' | sort -u)"
if [ -z "$crates" ]; then
    echo "cargo tree printed no crates for $PACKAGE on $TARGET; refusing to pass an empty graph" >&2
    exit 2
fi
found="$(printf '%s\n' "$crates" | grep -E "$BANNED" || true)"
if [ -n "$found" ]; then
    echo "Classical signature crates in the $PACKAGE $TARGET build graph:" >&2
    printf '  %s\n' $found >&2
    for crate in $found; do
        cargo tree --package "$PACKAGE" --target "$TARGET" --edges normal --invert "$crate" >&2 || true
    done
    exit 1
fi
echo "No classical signature crate in the $PACKAGE $TARGET build graph ($(printf '%s\n' "$crates" | wc -l | tr -d ' ') crates checked)."
