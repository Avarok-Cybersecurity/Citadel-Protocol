#!/bin/sh

# Get the NAT type from environment variable (default to none)
NAT_TYPE=${NAT_TYPE}

# Get the container IP address from hostname command
CONTAINER_IP=$(hostname -i)

# Get the subnet
SUBNET=$(ip addr show dev eth0 | grep inet | head -1 | awk '{print $2}')

echo "NAT TYPE: $NAT_TYPE"
echo "Container IP: $CONTAINER_IP"
echo "Subnet: $SUBNET"

# Set up simulated latency
tc qdisc add dev eth0 root netem delay 100ms

# Enable IP forwarding
# echo 1 > /proc/sys/net/ipv4/ip_forward

# Flush existing rules
iptables -F
iptables -t nat -F

# Configure iptables rules based on NAT type
case $NAT_TYPE in

  none)
    # No NAT translation (use default rules)
    echo "No NAT translation for $CONTAINER_IP"
    exit 1
  ;;

  full_cone)
    # Full-cone NAT (one-to-one mapping of IP and port)
    iptables -A INPUT -i eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to-source $CONTAINER_IP
    iptables -t nat -A PREROUTING -i eth0 -j DNAT --to-destination $CONTAINER_IP

    echo "Full-cone NAT translation for $CONTAINER_IP"
   ;;

   symmetric)
     # Symmetric NAT (different mapping of IP and port for each destination)

     echo 1 >/proc/sys/net/ipv4/ip_forward

     iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE --random-fully
     iptables -A FORWARD -i eth0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
     iptables -A FORWARD -i eth0 -o eth0 -j ACCEPT

     echo "Symmetric NAT translation for $CONTAINER_IP"
   ;;

   port_restricted)
     # Port-restricted NAT (same mapping of IP and port for each destination, but only allow incoming packets from same source port)

     iptables -t nat -A POSTROUTING -o eth0 -p udp -j SNAT --to-source $CONTAINER_IP

     echo "Port-restricted NAT translation for $CONTAINER_IP"
   ;;

   address_restricted)
     # Address-restricted NAT (same mapping of IP and port for each destination, but only allow incoming packets from same source address)

     iptables -t nat -A PREROUTING -i eth0 -p udp -d $CONTAINER_IP -j DNAT --to-destination $CONTAINER_IP
     iptables -t nat -A PREROUTING -i eth0 -p tcp -d $CONTAINER_IP -j DNAT --to-destination $CONTAINER_IP
     iptables -t nat -A POSTROUTING ! -d $SUBNET -m addrtype ! --dst-type LOCAL -j MASQUERADE

     # Accept expected incoming NEW traffic on all ports (all ports mapped)
     iptables -A INPUT -i eth0 -p udp -m state --state NEW -j ACCEPT
     iptables -A INPUT -i eth0 -p tcp -m state --state NEW -j ACCEPT

     # Accept RELATED/ESTAB traffic and drop other unexpected
     iptables -A INPUT -i eth0 -p udp -m state --state ESTABLISHED,RELATED -j ACCEPT
     iptables -A INPUT -i eth0 -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
     iptables -A INPUT -j DROP

     echo "Address-restricted NAT translation for $CONTAINER_IP"
    ;;
esac