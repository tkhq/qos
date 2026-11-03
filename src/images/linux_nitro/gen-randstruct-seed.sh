#!/bin/sh
# Match the upstream generator's interface, using a reproducible, public seed.
# This diversifies layouts between configurations, not between reproductions.
set -eu
seed=$(sha256sum .config | cut -d ' ' -f 1)
printf '%s\n' "$seed" > "$1"
hash=$(printf '%s' "$seed" | sha256sum | cut -d ' ' -f 1)
printf '#define RANDSTRUCT_HASHED_SEED "%s"\n' "$hash" > "$2"
