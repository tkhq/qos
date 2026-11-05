#!/bin/sh
set -eu
checker=$(dirname "$0")/check-config.sh
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
