#!/usr/bin/env bash
set -e
echo "Running set_nat.sh ..."
./set_nat.sh
echo "running server ..."
server
exec "$@"