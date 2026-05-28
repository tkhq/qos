#!/bin/sh

set -eu

DEFINT="${1:-${QOS_BRIDGE_EGRESS_INTERFACE:-eth0}}"

if [ "$(id -u)" != "0" ]; then
	echo "enclave_egress_interfaces.sh must run as root" >&2
	exit 1
fi

if [ ! -c /dev/net/tun ]; then
	echo "/dev/net/tun is not available; provide the TUN device to this container" >&2
	exit 1
fi

# create egress from host tun interface
if ! ip link show dev host_egress >/dev/null 2>&1; then
	ip tuntap add host_egress mode tun
fi

# assign 172.29.107.66/28 to host_egress to mask the martians
if ! ip address show dev host_egress | grep -q "172.29.107.66/28"; then
	ip address add 172.29.107.66/28 dev host_egress
fi

# bring the interface up
ip link set host_egress up

# ensure forwarding is going to go through
printf '1\n' > /proc/sys/net/ipv4/ip_forward

# masquerade nat for egress
if ! iptables -t nat -C POSTROUTING -s 172.29.107.65 -o eth0 -j MASQUERADE 2>/dev/null; then
	iptables -t nat -I POSTROUTING -s 172.29.107.65 -o eth0 -j MASQUERADE
fi

# check it
ip a show dev host_egress
