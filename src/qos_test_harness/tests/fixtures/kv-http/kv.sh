#!/bin/sh
set -u

name=
sync=1
for pair in $(printf '%s' "${QUERY_STRING:-}" | tr '&' ' '); do
	case "$pair" in
		name=*) name=${pair#name=} ;;
		sync=0) sync=0 ;;
	esac
done

# With its length: a close-delimited body never ends where the QEMU
# harness's vhost-device-vsock drops a half-close.
reply() {
	printf 'Status: %s\r\nContent-Type: text/plain\r\nContent-Length: %s\r\n\r\n%s' \
		"$1" "$(printf '%s' "$2" | wc -c)" "$2"
	exit 0
}

case "$name" in
	'' | *[!a-z0-9-]*) reply '400 Bad Request' 'a name is lowercase letters, digits and hyphens' ;;
esac
file="/data/$name"

case "${REQUEST_METHOD:-}" in
	GET)
		[ -f "$file" ] || reply '404 Not Found' ''
		reply '200 OK' "$(cat "$file")"
		;;
	POST)
		head -c "${CONTENT_LENGTH:-0}" > "$file.new" && mv "$file.new" "$file" ||
			reply '500 Internal Server Error' 'write failed'
		if [ "$sync" = 1 ]; then
			sync -f "$file" || reply '500 Internal Server Error' 'sync failed'
		fi
		reply '200 OK' ''
		;;
	*) reply '405 Method Not Allowed' '' ;;
esac
