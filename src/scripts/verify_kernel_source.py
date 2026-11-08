#!/usr/bin/env python3
"""Verify that the kernel tarball pinned in the linux_nitro Containerfile is
the release a kernel maintainer signed.

Usage: python3 src/scripts/verify_kernel_source.py

Reads the tarball URL and sha256 pin from the Containerfile, downloads the
tarball and its kernel.org signature, checks the pin, then checks the
signature against the maintainer keys committed in keys/. Only those keys are
trusted. Requires Python 3.11+, gpg, and gpgv.
"""

import hashlib
import lzma
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

IMAGE_DIR = Path("src/images/linux_nitro")
CONTAINERFILE = IMAGE_DIR / "Containerfile"


def find_exactly_one(pattern: str, text: str, what: str) -> str:
    matches = re.findall(pattern, text)
    if len(matches) != 1:
        sys.exit(f"expected one {what} in {CONTAINERFILE}, found {len(matches)}")
    return matches[0]


def main() -> None:
    containerfile = CONTAINERFILE.read_text()
    url = find_exactly_one(
        r"https://cdn\.kernel\.org/\S+\.tar\.xz", containerfile, "kernel.org .tar.xz URL"
    )
    pin = find_exactly_one(
        r"checksum=sha256:([0-9a-f]{64})", containerfile, "sha256 checksum"
    )

    with tempfile.TemporaryDirectory() as work_dir:
        work = Path(work_dir)
        tarball = work / "linux.tar.xz"
        signature = work / "linux.tar.sign"
        keyring = work / "keyring.gpg"

        urllib.request.urlretrieve(url, tarball)
        urllib.request.urlretrieve(url.removesuffix(".xz") + ".sign", signature)

        with tarball.open("rb") as f:
            actual = hashlib.file_digest(f, "sha256").hexdigest()
        if actual != pin:
            sys.exit(f"sha256 mismatch for {url}: pinned {pin}, got {actual}")

        # gpgv needs a binary keyring, so convert the armored .asc keys.
        armored_keys = b"".join(
            key.read_bytes() for key in sorted((IMAGE_DIR / "keys").glob("*.asc"))
        )
        dearmor = subprocess.run(
            ["gpg", "--dearmor"], input=armored_keys, capture_output=True, check=True
        )
        keyring.write_bytes(dearmor.stdout)

        # kernel.org signs the uncompressed tar, not the .xz. The tar is over
        # 1 GB, so stream it into gpgv instead of holding it in memory.
        with lzma.open(tarball) as tar, subprocess.Popen(
            ["gpgv", "--keyring", keyring, signature, "-"], stdin=subprocess.PIPE
        ) as gpgv:
            shutil.copyfileobj(tar, gpgv.stdin)
            gpgv.stdin.close()
        if gpgv.returncode != 0:
            sys.exit(f"signature check failed for {url}")

    print(f"verified {url}")


if __name__ == "__main__":
    main()
