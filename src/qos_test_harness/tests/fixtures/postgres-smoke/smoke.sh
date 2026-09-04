#!/bin/sh
set -eu

docker-entrypoint.sh postgres &
postgres_pid=$!
trap 'kill -TERM "$postgres_pid" 2>/dev/null || true' EXIT

attempt=0
until [ "$(psql -qAt -U postgres -d qos_test -c 'SELECT 1' 2>/dev/null || true)" = "1" ]; do
	attempt=$((attempt + 1))
	[ "$attempt" -lt 120 ] || exit 1
	sleep 0.25
done

result="$(psql -qAt -U postgres -d qos_test <<'SQL'
CREATE TABLE qos_smoke (id integer PRIMARY KEY, value text NOT NULL);
INSERT INTO qos_smoke VALUES (1, 'alpha'), (2, 'beta');
SELECT string_agg(value, ',' ORDER BY id) FROM qos_smoke;
SQL
)"
[ "$result" = "alpha,beta" ]

trap - EXIT
kill -TERM "$postgres_pid"
wait "$postgres_pid"
