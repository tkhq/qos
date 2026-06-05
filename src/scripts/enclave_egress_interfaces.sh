#!/bin/bash
#

set -e

DEFINT="${1:-eth0}"

# create egress from host tun interface
sudo ip tuntap add host_egress mode tun

# assign 10.0.0.2/28 to host_egress to mask the martians
sudo ip address add 172.29.107.66/28 dev host_egress

# bring the interface up
sudo ip link set host_egress up

# ensure forwarding is going to go through
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
sudo iptables -P FORWARD ACCEPT

# masquerade nat for egress
sudo iptables -t nat -I POSTROUTING -s 172.29.107.65 -j MASQUERADE -o "$DEFINT"

# check it
ip a show dev host_egress
