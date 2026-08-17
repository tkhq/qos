#!/usr/bin/env bash

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
demo_root="$(mktemp -d "${TMPDIR:-/tmp}/qos-hex-slop.XXXXXX")"
slop_worktree="${demo_root}/slop"
hex_worktree="${demo_root}/hexagonal"
hex_patch="${repo_root}/talk/patches/hexagonal-transport.patch"
recording_patch="${repo_root}/talk/patches/recording-adapter.patch"

git -C "${repo_root}" apply --check "${hex_patch}"
git -C "${repo_root}" worktree add --detach "${slop_worktree}" HEAD
git -C "${repo_root}" worktree add --detach "${hex_worktree}" HEAD
git -C "${hex_worktree}" apply "${hex_patch}"
git -C "${hex_worktree}" apply --check "${recording_patch}"

printf '%s\n' \
	"Demo worktrees are ready:" \
	"  baseline:  ${slop_worktree}" \
	"  hexagonal: ${hex_worktree}" \
	"" \
	"Open genuinely new Codex sessions:" \
	"  codex -C ${slop_worktree}" \
	"  codex -C ${hex_worktree}" \
	"" \
	"The script does not remove worktrees. Cleanup is intentionally manual."
