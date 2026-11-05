#!/bin/sh
# Check the resolved config, since Kconfig silently drops unmet dependencies.
set -eu
policy=$1
resolved=$2
failed=0
while IFS= read -r setting; do
	case "$setting" in
		CONFIG_*=*) ;;
		'# CONFIG_'*' is not set') ;;
		*) continue ;;
	esac
	# A disabled symbol may be omitted entirely when its parent is disabled.
	case "$setting" in
		'# CONFIG_'*' is not set')
			symbol=${setting#\# }
			symbol=${symbol% is not set}
			if ! grep -q "^${symbol}=" "$resolved"; then continue; fi
			;;
	esac
	if ! grep -Fqx "$setting" "$resolved"; then
		echo "Kernel hardening requirement not satisfied: $setting" >&2
		failed=1
	fi
done < "$policy"
exit "$failed"
