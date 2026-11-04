#!/bin/sh
# Fail if a release Containerfile has a FROM that could pull an image
# that is not pinned.
#
# Usage: check_image_refs.sh [Containerfile...]
#
# Each FROM must name one of:
# - scratch
# - a stage defined earlier in the same file
# - a local image under qos.invalid/, which never resolves to a registry
# - an image pinned by @sha256 digest
set -eu

[ "$#" -gt 0 ] || set -- src/images/*/Containerfile

awk '
	FNR == 1 { delete stages }
	toupper($1) == "FROM" {
		image = ""
		for (i = 2; i <= NF; i++) {
			if ($i !~ /^--/) { image = $i; break }
		}
		for (j = i + 1; j < NF; j++) {
			if (toupper($j) == "AS") stages[$(j + 1)] = 1
		}
		if (image == "scratch" || image in stages) next
		if (image ~ /^qos\.invalid\//) next
		digest = substr(image, index(image, "@sha256:") + 8)
		if (index(image, "@sha256:") && digest ~ /^[0-9a-f]+$/ && length(digest) == 64) next
		printf "%s:%d: unpinned image %s\n", FILENAME, FNR, image
		bad = 1
	}
	END { exit bad }
' "$@"
