#!/usr/bin/env python3
"""Fail when a lockfile gains a crates.io release younger than a minimum age.

This compares each lockfile against a base git ref and looks up the publish
time of every registry entry that is new since then in the crates.io sparse
index.

Usage: check_crate_age.py --base <git ref> [--days N] LOCKFILE...
"""

import argparse
import datetime
import json
import re
import subprocess
import sys
import urllib.request

INDEX = "https://index.crates.io"
USER_AGENT = "tkhq-qos-ci (https://github.com/tkhq/qos)"


def registry_entries(text):
	entries = set()
	for block in text.split("[[package]]")[1:]:
		if 'source = "registry+' not in block:
			continue
		name = re.search(r'^name = "([^"]+)"', block, re.M).group(1)
		version = re.search(r'^version = "([^"]+)"', block, re.M).group(1)
		entries.add((name, version))
	return entries


def index_path(name):
	name = name.lower()
	if len(name) <= 2:
		return f"{len(name)}/{name}"
	if len(name) == 3:
		return f"3/{name[0]}/{name}"
	return f"{name[:2]}/{name[2:4]}/{name}"


def publish_time(name, version):
	request = urllib.request.Request(
		f"{INDEX}/{index_path(name)}", headers={"User-Agent": USER_AGENT}
	)
	with urllib.request.urlopen(request, timeout=30) as response:
		for line in response.read().decode().splitlines():
			entry = json.loads(line)
			if entry["vers"] == version:
				return entry.get("pubtime")
	return None


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--base", required=True)
	parser.add_argument("--days", type=int, default=7)
	parser.add_argument("lockfiles", nargs="+")
	args = parser.parse_args()

	cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
		days=args.days
	)
	failures = []
	for lockfile in args.lockfiles:
		with open(lockfile) as f:
			current = registry_entries(f.read())
		base = subprocess.run(
			["git", "show", f"{args.base}:{lockfile}"],
			capture_output=True,
			text=True,
		)
		previous = registry_entries(base.stdout) if base.returncode == 0 else set()
		for name, version in sorted(current - previous):
			published = publish_time(name, version)
			if published is None:
				failures.append(f"{lockfile}: {name} {version} has no publish time")
				continue
			published_at = datetime.datetime.fromisoformat(
				published.replace("Z", "+00:00")
			)
			if published_at > cutoff:
				failures.append(
					f"{lockfile}: {name} {version} was published {published}"
				)
		print(f"{lockfile}: {len(current - previous)} new registry entries checked")

	if failures:
		print(
			f"\nReleases younger than {args.days} days. Pin them to an older "
			"version with `cargo update -p <crate> --precise <version>`:"
		)
		print("\n".join(f"  {f}" for f in failures))
		sys.exit(1)


if __name__ == "__main__":
	main()
