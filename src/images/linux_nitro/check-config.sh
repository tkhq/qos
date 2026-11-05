#!/bin/sh
# Usage: check-config.sh POLICY CONFIG
#
# Fails if the final kernel CONFIG does not match every setting in POLICY.
# Kconfig silently drops settings whose dependencies are not met, so the
# build checks the final .config instead of trusting the merged fragment.
set -eu
policy=$1
config=$2
failed=0

while IFS= read -r line; do
	case "$line" in
	CONFIG_*)
		# Enabled setting, like "CONFIG_FOO=y": CONFIG must contain this exact line.
		if ! grep -qFx "$line" "$config"; then
			echo "Kernel hardening setting missing: $line" >&2
			failed=1
		fi
		;;
	"# CONFIG_"*" is not set")
		# Disabled setting, like "# CONFIG_FOO is not set": CONFIG must not set
		# CONFIG_FOO. Kconfig can omit the symbol entirely, which also counts.
		symbol=$(echo "$line" | cut -d ' ' -f 2)
		if grep -q "^$symbol=" "$config"; then
			echo "Kernel hardening setting must be disabled: $symbol" >&2
			failed=1
		fi
		;;
	esac
done < "$policy"

exit "$failed"
