#!/bin/sh
set -eu
checker=$(dirname "$0")/check-config.sh
seed_generator=$(cd "$(dirname "$0")" && pwd)/gen-randstruct-seed.sh
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
cat > "$test_dir/policy" <<'EOF'
CONFIG_REQUIRED=y
# CONFIG_FORBIDDEN is not set
CONFIG_LIMIT=65536
EOF
cat > "$test_dir/resolved" <<'EOF'
CONFIG_REQUIRED=y
CONFIG_LIMIT=65536
EOF
# Kconfig can omit disabled symbols when their parent is disabled.
sh "$checker" "$test_dir/policy" "$test_dir/resolved"
for bad in 'CONFIG_REQUIRED=n' 'CONFIG_FORBIDDEN=y' 'CONFIG_LIMIT=4096'; do
	cat > "$test_dir/good" <<'EOF'
CONFIG_REQUIRED=y
CONFIG_LIMIT=65536
EOF
	symbol=${bad%%=*}
	sed "/^${symbol}=/d" "$test_dir/good" > "$test_dir/resolved"
	printf '%s\n' "$bad" >> "$test_dir/resolved"
	if sh "$checker" "$test_dir/policy" "$test_dir/resolved" 2>/dev/null; then
		echo "Checker accepted conflicting setting: $bad" >&2
		exit 1
	fi
done
printf '%s\n' '# CONFIG_FORBIDDEN is not set' > "$test_dir/resolved"
if sh "$checker" "$test_dir/policy" "$test_dir/resolved" 2>/dev/null; then
	echo 'Checker accepted missing required settings' >&2
	exit 1
fi
# A fresh build of the same config must produce the same RANDSTRUCT seed/hash.
cp "$test_dir/policy" "$test_dir/.config"
(
	cd "$test_dir"
	sh "$seed_generator" seed-a hash-a
	sh "$seed_generator" seed-b hash-b
	cmp seed-a seed-b
	cmp hash-a hash-b
	printf '%s\n' 'CONFIG_ANOTHER=y' >> .config
	sh "$seed_generator" seed-c hash-c
	if cmp -s seed-a seed-c; then
		echo 'RANDSTRUCT seed did not change with the config' >&2
		exit 1
	fi
)
