#!/bin/sh

set -eu

if [ "${QOS_BRIDGE_SKIP_EGRESS_SETUP:-0}" != "1" ]; then
	/enclave_egress_interfaces.sh "${QOS_BRIDGE_EGRESS_INTERFACE:-eth0}"
fi

exec /qos_bridge "$@"
