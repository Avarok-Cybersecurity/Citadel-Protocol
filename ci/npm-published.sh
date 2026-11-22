#!/usr/bin/env bash
# Prints `true` when <package>@<version> is on the npm registry and `false` when the registry
# answers that it is not (E404). Any other failure (network, auth, a registry outage) fails this
# script: read as "not published", it would send the publish step on to publish, or to report a
# version that is on npm as new.
#
# Usage: ci/npm-published.sh <package> <version>
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 <package> <version>" >&2
  exit 2
fi
spec="$1@$2"
err="$(mktemp)"
trap 'rm -f "$err"' EXIT

if out="$(npm view "$spec" version --json 2>"$err")"; then
  case "$out" in
    "\"$2\"") echo true ;;
    # npm 10 and earlier succeed, printing nothing, for a version the package does not have.
    "") echo false ;;
    *)
      echo "npm-published: unexpected answer for $spec: $out" >&2
      exit 1
      ;;
  esac
elif grep -q 'E404' "$err" || printf '%s' "$out" | grep -q '"E404"'; then
  echo false
else
  echo "npm-published: could not look up $spec:" >&2
  cat "$err" >&2
  exit 1
fi
