#!/bin/sh
# Serve the files in /data over HTTP on port 3000: `POST /cgi-bin/kv?name=N`
# with the value as the body writes N, then syncs its filesystem unless the
# query has `sync=0`; `GET /cgi-bin/kv?name=N` reads it. Names are lowercase
# letters, digits and hyphens.
set -eu
mkdir -p /data
echo "kv-http: serving /data on port 3000"
exec httpd -f -p 0.0.0.0:3000 -h /www
