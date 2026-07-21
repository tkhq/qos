set -eu
if ! ip link show host_egress >/dev/null 2>&1; then
	ip tuntap add host_egress mode tun || true
fi
for _ in $(seq 1 120); do
	if ip link show host_egress >/dev/null 2>&1; then
		break
	fi
	sleep 0.25
done
ip link show host_egress >/dev/null
ip link set mtu 1320 dev host_egress
ip link set host_egress up
ip route replace 169.254.0.1/32 dev host_egress
DEFAULT_IF="$(ip route show default | awk '{ print $5; exit }')"
if [ -z "${DEFAULT_IF}" ]; then
	DEFAULT_IF="$(ip route get 8.8.8.8 | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
fi
if [ -z "${DEFAULT_IF}" ]; then
	echo "unable to determine default egress interface" >&2
	exit 1
fi
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.host_egress.rp_filter=0
sysctl -w "net.ipv4.conf.${DEFAULT_IF}.rp_filter=0"
NFQUEUE_NUM="${QOS_TEST_HARNESS_EGRESS_NFQUEUE_NUM:-100}"
IPTABLES=""
for candidate in iptables-legacy iptables; do
	if command -v "${candidate}" >/dev/null 2>&1 \
		&& "${candidate}" -t filter -L >/dev/null 2>&1 \
		&& "${candidate}" -t raw -L >/dev/null 2>&1 \
		&& "${candidate}" -t nat -L >/dev/null 2>&1; then
		IPTABLES="$(command -v "${candidate}")"
		break
	fi
done
if [ -z "${IPTABLES}" ]; then
	echo "unable to find an iptables backend with filter, raw, and nat tables" >&2
	exit 1
fi
"${IPTABLES}" -C FORWARD -i host_egress -o "${DEFAULT_IF}" -j ACCEPT 2>/dev/null || "${IPTABLES}" -I FORWARD -i host_egress -o "${DEFAULT_IF}" -j ACCEPT
"${IPTABLES}" -C FORWARD -i "${DEFAULT_IF}" -o host_egress -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || "${IPTABLES}" -I FORWARD -i "${DEFAULT_IF}" -o host_egress -m state --state RELATED,ESTABLISHED -j ACCEPT
"${IPTABLES}" -D FORWARD -o host_egress -p tcp -j NFQUEUE --queue-num "${NFQUEUE_NUM}" --queue-bypass 2>/dev/null || true
"${IPTABLES}" -I FORWARD 1 -o host_egress -p tcp -j NFQUEUE --queue-num "${NFQUEUE_NUM}" --queue-bypass
"${IPTABLES}" -t raw -D PREROUTING -i host_egress -p udp -j NFQUEUE --queue-num "${NFQUEUE_NUM}" --queue-bypass 2>/dev/null || true
"${IPTABLES}" -t raw -I PREROUTING 1 -i host_egress -p udp -j NFQUEUE --queue-num "${NFQUEUE_NUM}" --queue-bypass
"${IPTABLES}" -D FORWARD -o host_egress -p udp -j NFQUEUE --queue-num "${NFQUEUE_NUM}" --queue-bypass 2>/dev/null || true
"${IPTABLES}" -I FORWARD 1 -o host_egress -p udp -j NFQUEUE --queue-num "${NFQUEUE_NUM}" --queue-bypass
"${IPTABLES}" -t nat -C POSTROUTING -s 169.254.0.1/32 -o "${DEFAULT_IF}" -j MASQUERADE 2>/dev/null || "${IPTABLES}" -t nat -I POSTROUTING -s 169.254.0.1/32 -o "${DEFAULT_IF}" -j MASQUERADE
