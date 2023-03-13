#!/bin/sh

# Set up simulated latency
tc qdisc add dev eth0 root netem delay 100ms

# Run the default command
exec "$@"
