# SPDX-License-Identifier: Apache-2.0
"""Require two package builds to be byte-for-byte identical."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifacts(directory: Path) -> dict[str, str]:
    result = {
        path.name: digest(path)
        for path in sorted(directory.iterdir())
        if path.is_file() and (path.suffix == ".whl" or path.name.endswith(".tar.gz"))
    }
    if not result:
        raise AssertionError(f"no Python artifacts found in {directory}")
    return result


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: compare_artifacts.py FIRST_BUILD SECOND_BUILD")
    first = artifacts(Path(sys.argv[1]))
    second = artifacts(Path(sys.argv[2]))
    if first != second:
        raise AssertionError(f"package builds differ: {first!r} != {second!r}")
    print(json.dumps(first, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
