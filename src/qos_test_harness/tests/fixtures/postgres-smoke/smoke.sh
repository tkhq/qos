#!/bin/sh
# Initialize, start, query and stop PostgreSQL in order, over its Unix socket:
# each step waits for the one before, so nothing races the server's startup.
set -eu

run() { su-exec postgres "$@"; }

run initdb -D "$PGDATA" --auth=trust --username=postgres
run pg_ctl -D "$PGDATA" -o "-c listen_addresses=''" -w -t 600 start
trap 'run pg_ctl -D "$PGDATA" -m fast -w stop || true' EXIT
run createdb -U postgres qos_test

result="$(run psql -qAt -U postgres -d qos_test <<'SQL'
CREATE TABLE qos_smoke (id integer PRIMARY KEY, value text NOT NULL);
INSERT INTO qos_smoke VALUES (1, 'alpha'), (2, 'beta');
SELECT string_agg(value, ',' ORDER BY id) FROM qos_smoke;
SQL
)"
[ "$result" = "alpha,beta" ]

trap - EXIT
run pg_ctl -D "$PGDATA" -m fast -w stop
