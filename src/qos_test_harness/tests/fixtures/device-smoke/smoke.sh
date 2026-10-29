#!/bin/sh
# A workload that mounts the NSM opens it and shares its device numbers on
# the shared volume; a workload without the mount finds no node, and its
# device policy refuses a node with those numbers: making it, or opening it.
set -eu

shared=/run/shared
if [ -e /dev/nsm ]; then
	[ -c /dev/nsm ]
	(exec 3<>/dev/nsm)
	stat -c '%t %T' /dev/nsm >"$shared/nsm.tmp"
	mv "$shared/nsm.tmp" "$shared/nsm"
	echo "nsm opened"
else
	attempt=0
	until [ -s "$shared/nsm" ]; do
		attempt=$((attempt + 1))
		[ "$attempt" -lt 600 ] || exit 2
		sleep 0.1
	done
	read -r major minor <"$shared/nsm"
	if mknod /dev/nsm-copy c "$((0x$major))" "$((0x$minor))" 2>/dev/null; then
		if (exec 3<>/dev/nsm-copy) 2>/dev/null; then
			echo "nsm opened without its mount"
			exit 1
		fi
		echo "nsm denied at open"
	else
		echo "nsm denied at mknod"
	fi
fi
