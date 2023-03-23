#!/usr/bin/env bash
echo "Running set_nat.sh ..."
./set_nat.sh
echo "running client ..."
client
exec "$@"