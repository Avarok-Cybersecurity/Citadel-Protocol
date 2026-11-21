#!/usr/bin/env bash
# cargo audit over the committed Cargo.lock, with deny.toml's advisory exceptions as its only ignores.
#
# cargo audit reads every lockfile entry, whatever feature or target pulls it in; cargo deny judges
# the graph it resolves. The two disagreed once (rsa, through the opt-in `sql` feature, was in the
# lockfile and outside deny's graph), so both run. Their exceptions are one list, deny.toml's
# `[advisories] ignore`; every entry there must carry a reason, or this refuses to run.
set -euo pipefail

ignores="$(python3 - <<'PY'
import sys, tomllib
entries = tomllib.load(open("deny.toml", "rb"))["advisories"].get("ignore", [])
bad = [e for e in entries if not (isinstance(e, dict) and e.get("id") and e.get("reason"))]
if bad:
    sys.exit(f"deny.toml advisory ignores without an id and a reason: {bad}")
print(" ".join(e["id"] for e in entries))
PY
)"

args=()
for id in $ignores; do args+=(--ignore "$id"); done
echo "cargo audit, ignoring (from deny.toml): ${ignores:-nothing}"
cargo audit --file Cargo.lock "${args[@]}"
