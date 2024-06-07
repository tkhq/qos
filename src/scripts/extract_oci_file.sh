#!/bin/sh
set -eu
tar=${1?}
path=${2?}
layer=$( \
    tar -tvf /out/${tar} 2>/dev/null\
	    | sort -k3 -n \
	    | tail -n1 \
	    | awk '{ print $6 }'\
)
cd /out
tar -xf /out/qos_enclave.tar ${layer}
tar -xzf ${layer} ${path}
rm -rf blobs
