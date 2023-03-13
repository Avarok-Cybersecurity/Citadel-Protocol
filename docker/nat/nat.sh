#!/bin/sh

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Set up full-cone NAT rules
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# point to the server
iptables -t nat -A PREROUTING -i eth0 -j DNAT --to-destination 172.16.238.12

# Enable forwarding of packets from any source
iptables -A FORWARD -i eth0 -o eth0 -j ACCEPT

# Keep the container running
tail -f /dev/null
