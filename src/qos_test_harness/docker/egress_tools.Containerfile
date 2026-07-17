# syntax=docker/dockerfile:1
FROM debian:bookworm-slim
RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		build-essential \
		dnsmasq \
		ethtool \
		iproute2 \
		iptables \
		libnetfilter-queue-dev \
		pkg-config \
		procps \
		tcpdump \
	&& rm -rf /var/lib/apt/lists/*
COPY nfqueue_checksum_fix.c /tmp/nfqueue_checksum_fix.c
RUN cc -O2 -Wall -Wextra -Werror \
		-o /usr/local/bin/qos-nfqueue-checksum-fix \
		/tmp/nfqueue_checksum_fix.c \
		$(pkg-config --cflags --libs libnetfilter_queue) \
	&& /usr/local/bin/qos-nfqueue-checksum-fix --self-test \
	&& rm /tmp/nfqueue_checksum_fix.c
