#!/bin/sh

# Get the NAT type from environment variable (default to none)
NAT_TYPE=${NAT_TYPE}

# Get the container IP address from hostname command
CONTAINER_IP=$(hostname -i)

echo "NAT TYPE: $NAT_TYPE"
echo "Container IP: $CONTAINER_IP"

# Set up simulated latency
tc qdisc add dev eth0 root netem delay 100ms

# Configure iptables rules based on NAT type

case $NAT_TYPE in

  none)
    # No NAT translation (use default rules)
    echo "No NAT translation for $CONTAINER_IP"
  ;;

  full_cone)
    # Full-cone NAT (one-to-one mapping of IP and port)

     # Enable IP forwarding
     echo 1 > /proc/sys/net/ipv4/ip_forward

     # Flush existing rules
     iptables -F
     iptables -t nat -F

     # Add MASQUERADE rule for outgoing packets
     iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

     # Add DNAT rule for incoming packets
     iptables -t nat -A PREROUTING -i eth0 -j DNAT --to-destination $CONTAINER_IP

     echo "Full-cone NAT translation for $CONTAINER_IP"
   ;;

   symmetric)
     # Symmetric NAT (different mapping of IP and port for each destination)

     # Enable IP forwarding
     echo 1 > /proc/sys/net/ipv4/ip_forward

     # Flush existing rules
     iptables -F
     iptables -t nat -F

     # Add MASQUERADE rule for outgoing packets with random port selection
     iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE --random

      echo "Symmetric NAT translation for $CONTAINER_IP"
   ;;

   port_restricted)
      # Port-restricted NAT (same mapping of IP and port for each destination, but only allow incoming packets from same source port)

      # Enable IP forwarding
      echo 1 > /proc/sys/net/ipv4/ip_forward

      # Flush existing rules
      iptables -F
      iptables -t nat -F

      # Add MASQUERADE rule for outgoing packets
      iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

      # Add DNAT rule for incoming packets with matching source port
      iptables -t nat -A PREROUTING -i eth0 -m state --state ESTABLISHED,RELATED -j DNAT --to-destination $CONTAINER_IP

      echo "Port-restricted NAT translation for $CONTAINER_IP"
   ;;

   address_restricted)
       # Address-restricted NAT (same mapping of IP and port for each destination, but only allow incoming packets from same source address)

       # Enable IP forwarding
       echo 1 > /proc/sys/net/ipv4/ip_forward

       # Flush existing rules
       iptables -F
       iptables -t nat -F

       # Add MASQUERADE rule for outgoing packets
       iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

       # Add DNAT rule for incoming packets with matching source address
       iptables -t nat -A PREROUTING -i eth0 -m state --state ESTABLISHED,RELATED -j DNAT--to-destination $CONTAINER_IP

       echo "Address-restricted NAT translation for $CONTAINER_IP"
    ;;
esac