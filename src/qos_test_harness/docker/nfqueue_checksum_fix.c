#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

/*
 * Docker Desktop can hand the QEMU egress namespace TCP or UDP packets whose
 * bytes still depend on checksum-offload metadata that is not present on a TUN
 * read. QOS production code should not learn about that Docker artifact. This
 * harness-only NFQUEUE helper sits in the Docker forwarding path and rewrites
 * ordinary IPv4 transport checksum bytes at the Docker forwarding boundary.
 */

static uint16_t read_be16(const unsigned char *bytes) {
	return (uint16_t)(((uint16_t)bytes[0] << 8) | (uint16_t)bytes[1]);
}

static void write_be16(unsigned char *bytes, uint16_t value) {
	bytes[0] = (unsigned char)(value >> 8);
	bytes[1] = (unsigned char)(value & 0xff);
}

static uint32_t checksum_add_bytes(
	uint32_t sum,
	const unsigned char *bytes,
	size_t len
) {
	size_t i = 0;
	for (; i + 1 < len; i += 2) {
		sum += read_be16(&bytes[i]);
	}
	if (i < len) {
		sum += (uint32_t)bytes[i] << 8;
	}
	return sum;
}

static uint16_t checksum_finish(uint32_t sum) {
	while ((sum >> 16) != 0) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return (uint16_t)(~sum);
}

static uint16_t checksum16(const unsigned char *bytes, size_t len) {
	return checksum_finish(checksum_add_bytes(0, bytes, len));
}

static uint16_t transport_checksum_ipv4(
	const unsigned char *packet,
	const unsigned char *transport,
	size_t transport_len,
	unsigned char protocol
) {
	uint32_t sum = 0;

	/*
	 * TCP and UDP checksums cover the transport segment plus the IPv4
	 * pseudo-header. The pseudo-header prevents a valid segment from being accepted if
	 * it was delivered for a different IPv4 source/destination/protocol.
	 */
	sum = checksum_add_bytes(sum, &packet[12], 4);
	sum = checksum_add_bytes(sum, &packet[16], 4);
	sum += protocol;
	sum += (uint32_t)transport_len;
	sum = checksum_add_bytes(sum, transport, transport_len);

	return checksum_finish(sum);
}

/*
 * Docker Desktop loses one reply when musl sends A and AAAA DNS requests from
 * the same UDP source port. Keep the DNS request and resolver unchanged, but
 * put AAAA traffic on a second host-side flow while it crosses Docker's
 * network. The same involution restores the guest's original port on replies.
 */
#define DNS_PORT 53
#define DNS_TYPE_AAAA 28
#define DNS_AAAA_PORT_MASK 0x4000

static int dns_question_type(
	const unsigned char *dns,
	size_t dns_len,
	uint16_t *question_type
) {
	if (dns_len < 12 || read_be16(&dns[4]) == 0) {
		return 0;
	}

	size_t offset = 12;
	while (offset < dns_len) {
		unsigned char label_len = dns[offset++];
		if (label_len == 0) {
			break;
		}
		if ((label_len & 0xc0) != 0 || label_len > 63
			|| offset + label_len > dns_len) {
			return 0;
		}
		offset += label_len;
	}
	if (offset + 4 > dns_len) {
		return 0;
	}

	*question_type = read_be16(&dns[offset]);
	return 1;
}

static int split_aaaa_dns_flow(unsigned char *packet, int len) {
	if (len < 28 || (packet[0] >> 4) != 4) {
		return 0;
	}

	size_t ihl = (size_t)(packet[0] & 0x0f) * 4;
	size_t total_len = read_be16(&packet[2]);
	if (ihl < 20 || total_len < ihl + 8 || (size_t)len < total_len
		|| packet[9] != IPPROTO_UDP) {
		return 0;
	}

	unsigned char *udp = &packet[ihl];
	size_t udp_len = read_be16(&udp[4]);
	if (udp_len < 8 || udp_len != total_len - ihl) {
		return 0;
	}

	uint16_t source_port = read_be16(&udp[0]);
	uint16_t destination_port = read_be16(&udp[2]);
	if (source_port != DNS_PORT && destination_port != DNS_PORT) {
		return 0;
	}

	const unsigned char *dns = &udp[8];
	size_t dns_len = udp_len - 8;
	uint16_t question_type = 0;
	if (!dns_question_type(dns, dns_len, &question_type)
		|| question_type != DNS_TYPE_AAAA) {
		return 0;
	}

	if (destination_port == DNS_PORT && (dns[2] & 0x80) == 0) {
		write_be16(&udp[0], source_port ^ DNS_AAAA_PORT_MASK);
		return 1;
	}
	if (source_port == DNS_PORT && (dns[2] & 0x80) != 0) {
		write_be16(&udp[2], destination_port ^ DNS_AAAA_PORT_MASK);
		return 1;
	}
	return 0;
}

static int repair_ipv4_transport_packet(unsigned char *packet, int len) {
	if (len < 20 || (packet[0] >> 4) != 4) {
		return 0;
	}

	size_t ihl = (size_t)(packet[0] & 0x0f) * 4;
	if (ihl < 20 || (size_t)len < ihl) {
		return 0;
	}

	size_t total_len = read_be16(&packet[2]);
	if (total_len < ihl || (size_t)len < total_len) {
		return 0;
	}

	/*
	 * Recompute the IPv4 header checksum as a cheap sanity repair. The
	 * observed Docker issue was TCP checksum bytes, but keeping the L3 header
	 * canonical makes the helper safe for packets that pass through a more
	 * exotic host path.
	 */
	packet[10] = 0;
	packet[11] = 0;
	write_be16(&packet[10], checksum16(packet, ihl));

	uint16_t flags_fragment = read_be16(&packet[6]);
	int is_fragmented = (flags_fragment & 0x3fff) != 0;
	if (is_fragmented || total_len < ihl + 8) {
		return 1;
	}

	unsigned char *transport = &packet[ihl];
	size_t transport_len = total_len - ihl;
	unsigned char protocol = packet[9];
	size_t checksum_offset;
	if (protocol == IPPROTO_TCP) {
		size_t tcp_header_len = (size_t)(transport[12] >> 4) * 4;
		if (tcp_header_len < 20 || transport_len < tcp_header_len) {
			return 1;
		}
		checksum_offset = 16;
	} else if (protocol == IPPROTO_UDP) {
		uint16_t udp_len = read_be16(&transport[4]);
		if (udp_len < 8 || udp_len != transport_len) {
			return 1;
		}
		checksum_offset = 6;
	} else {
		return 1;
	}

	/*
	 * The kernel has already decided this forwarded packet is acceptable in
	 * the Docker namespace. The problem is that the raw bytes reaching TUN do
	 * not carry the kernel's checksum/offload metadata. Always materialize the
	 * transport checksum bytes so subsequent networking layers receive a
	 * self-contained IP packet.
	 */
	transport[checksum_offset] = 0;
	transport[checksum_offset + 1] = 0;
	uint16_t checksum = transport_checksum_ipv4(
		packet,
		transport,
		transport_len,
		protocol
	);
	if (protocol == IPPROTO_UDP && checksum == 0) {
		checksum = 0xffff;
	}
	write_be16(&transport[checksum_offset], checksum);

	return 1;
}

static int queue_callback(
	struct nfq_q_handle *qh,
	struct nfgenmsg *nfmsg,
	struct nfq_data *nfa,
	void *data
) {
	(void)nfmsg;
	(void)data;

	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
	uint32_t id = 0;
	if (ph != NULL) {
		id = ntohl(ph->packet_id);
	}

	unsigned char *payload = NULL;
	int payload_len = nfq_get_payload(nfa, &payload);
	if (payload_len <= 0) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	unsigned char *packet = malloc((size_t)payload_len);
	if (packet == NULL) {
		perror("malloc");
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	memcpy(packet, payload, (size_t)payload_len);
	split_aaaa_dns_flow(packet, payload_len);
	repair_ipv4_transport_packet(packet, payload_len);

	int rc = nfq_set_verdict(
		qh,
		id,
		NF_ACCEPT,
		(uint32_t)payload_len,
		packet
	);
	free(packet);
	return rc;
}

static int self_test(void) {
	unsigned char packet[40] = {
		0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00, 0x5d, 0xb8, 0xd8, 0x22,
		0xac, 0x1d, 0x6b, 0x41, 0x01, 0xbb, 0xd4, 0x31,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
		0x50, 0x12, 0x72, 0x10, 0x12, 0x34, 0x00, 0x00,
	};

	repair_ipv4_transport_packet(packet, (int)sizeof(packet));
	if (checksum16(packet, 20) != 0) {
		fprintf(stderr, "self-test: IPv4 checksum is invalid\n");
		return 1;
	}
	if (transport_checksum_ipv4(packet, &packet[20], 20, IPPROTO_TCP) != 0) {
		fprintf(stderr, "self-test: TCP checksum is invalid\n");
		return 1;
	}

	unsigned char udp_packet[28] = {
		0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01,
		0xa9, 0xfe, 0x00, 0x01, 0x00, 0x35, 0xd4, 0x31,
		0x00, 0x08, 0x12, 0x34,
	};
	repair_ipv4_transport_packet(udp_packet, (int)sizeof(udp_packet));
	uint32_t udp_sum = 0;
	udp_sum = checksum_add_bytes(udp_sum, &udp_packet[12], 4);
	udp_sum = checksum_add_bytes(udp_sum, &udp_packet[16], 4);
	udp_sum += IPPROTO_UDP;
	udp_sum += 8;
	udp_sum = checksum_add_bytes(udp_sum, &udp_packet[20], 8);
	if (checksum_finish(udp_sum) != 0) {
		fprintf(stderr, "self-test: UDP checksum is invalid\n");
		return 1;
	}

	unsigned char dns_query[57] = {
		0x45, 0x00, 0x00, 0x39, 0x12, 0x34, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0xa9, 0xfe, 0x00, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x91, 0xb5, 0x00, 0x35,
		0x00, 0x25, 0x00, 0x00, 0xb6, 0xae, 0x01, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00, 0x00, 0x1c, 0x00,
		0x01,
	};
	if (!split_aaaa_dns_flow(dns_query, (int)sizeof(dns_query))
		|| read_be16(&dns_query[20]) != (uint16_t)(0x91b5 ^ 0x4000)) {
		fprintf(stderr, "self-test: AAAA query flow was not split\n");
		return 1;
	}
	dns_query[30] |= 0x80;
	write_be16(&dns_query[20], DNS_PORT);
	write_be16(&dns_query[22], (uint16_t)(0x91b5 ^ 0x4000));
	if (!split_aaaa_dns_flow(dns_query, (int)sizeof(dns_query))
		|| read_be16(&dns_query[22]) != 0x91b5) {
		fprintf(stderr, "self-test: AAAA response port was not restored\n");
		return 1;
	}

	return 0;
}

static void usage(const char *program) {
	fprintf(stderr, "usage: %s [--queue NUM] [--self-test]\n", program);
}

int main(int argc, char **argv) {
	uint16_t queue_num = 100;

	static const struct option options[] = {
		{"queue", required_argument, NULL, 'q'},
		{"self-test", no_argument, NULL, 't'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0},
	};

	for (;;) {
		int opt = getopt_long(argc, argv, "q:th", options, NULL);
		if (opt == -1) {
			break;
		}
		switch (opt) {
		case 'q': {
			long parsed = strtol(optarg, NULL, 10);
			if (parsed < 0 || parsed > 65535) {
				fprintf(stderr, "invalid queue number: %s\n", optarg);
				return 2;
			}
			queue_num = (uint16_t)parsed;
			break;
		}
		case 't':
			return self_test();
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	struct nfq_handle *h = nfq_open();
	if (h == NULL) {
		perror("nfq_open");
		return 1;
	}

	/*
	 * Binding AF_INET here is process-local NFQUEUE setup. The actual packet
	 * selection is still controlled by the runner's iptables rule in the
	 * Docker egress namespace.
	 */
	(void)nfq_unbind_pf(h, AF_INET);
	if (nfq_bind_pf(h, AF_INET) < 0) {
		perror("nfq_bind_pf");
		nfq_close(h);
		return 1;
	}

	struct nfq_q_handle *qh =
		nfq_create_queue(h, queue_num, &queue_callback, NULL);
	if (qh == NULL) {
		perror("nfq_create_queue");
		nfq_close(h);
		return 1;
	}

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		perror("nfq_set_mode");
		nfq_destroy_queue(qh);
		nfq_close(h);
		return 1;
	}

	int fd = nfq_fd(h);
	char buf[65536] __attribute__((aligned));
	fprintf(stderr, "qos-nfqueue-checksum-fix: listening on queue %u\n", queue_num);
	for (;;) {
		int rv = recv(fd, buf, sizeof(buf), 0);
		if (rv >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		if (errno == EINTR) {
			continue;
		}
		perror("recv");
		break;
	}

	nfq_destroy_queue(qh);
	nfq_close(h);
	return 1;
}
