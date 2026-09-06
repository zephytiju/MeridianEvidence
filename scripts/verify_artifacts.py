# SPDX-License-Identifier: Apache-2.0
"""Verify wheel and sdist contents, metadata, boundaries, and hashes."""

from __future__ import annotations

import hashlib
import json
import sys
import tarfile
import zipfile
from email.parser import Parser
from pathlib import Path
from typing import Any

PACKAGE = "meridian_storage/evidence/"
REQUIRED_WHEEL_SUFFIXES = {
    "LICENSE",
    "NOTICE",
    "meridian_storage/evidence/compatibility.json",
    "meridian_storage/evidence/contracts/catalogs/meridian-evidence-catalog.v1.json",
    "meridian_storage/evidence/contracts/public-api/meridian-evidence.v1.json",
    "meridian_storage/evidence/contracts/schemas/meridian.evidence.common.v1.schema.json",
    "meridian_storage/evidence/py.typed",
}
REQUIRED_SDIST_SUFFIXES = {
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "NOTICE",
    "README.md",
    "RELEASING.md",
    "SECURITY.md",
    "compatibility.json",
    "pyproject.toml",
    "scripts/verify_contracts.py",
    "src/meridian_storage/evidence/__init__.py",
    "tests/conformance/test_schemas_and_goldens.py",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _has_suffix(names: set[str], suffix: str) -> bool:
    return any(name == suffix or name.endswith("/" + suffix) for name in names)


def verify_wheel(path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        assert all(_has_suffix(names, suffix) for suffix in REQUIRED_WHEEL_SUFFIXES)
        assert "meridian_storage/__init__.py" not in names
        assert not any(
            part in name for name in names for part in ("/__pycache__/", "/.git/", "tests/")
        )
        python_packages = {
            name.rsplit("/", 1)[0]
            for name in names
            if name.endswith("/__init__.py") and ".dist-info/" not in name
        }
        assert python_packages == {"meridian_storage/evidence"}
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = Parser().parsestr(archive.read(metadata_name).decode("utf-8"))
        assert metadata["Name"] == "meridian-storage-evidence"
        assert metadata["Version"] == "1.0.1"
        assert metadata["License-Expression"] == "Apache-2.0"
        dependencies = set(metadata.get_all("Requires-Dist", []))
        assert "meridian-storage-core==1.0.1" in dependencies
        assert "meridian-storage-semantics==2.0.0" in dependencies
        entry_name = next(name for name in names if name.endswith(".dist-info/entry_points.txt"))
        entry_points = archive.read(entry_name).decode("utf-8")
        assert "meridian_storage.catalogs" in entry_points
        assert "EvidenceCatalogProvider" in entry_points
        assert "meridian_storage.schemas" in entry_points
        assert "EvidenceSchemaProvider" in entry_points
    return {"filename": path.name, "sha256": digest(path), "type": "wheel"}


def verify_sdist(path: Path) -> dict[str, Any]:
    with tarfile.open(path, "r:gz") as archive:
        names = set(archive.getnames())
        assert all(_has_suffix(names, suffix) for suffix in REQUIRED_SDIST_SUFFIXES)
        assert not any("/__pycache__/" in name or "/.git/" in name for name in names)
        assert not _has_suffix(names, "src/meridian_storage/__init__.py")
    return {"filename": path.name, "sha256": digest(path), "type": "sdist"}


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_artifacts.py DIST_DIRECTORY")
    directory = Path(sys.argv[1])
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise AssertionError("artifact directory must contain exactly one wheel and one sdist")
    result = [verify_wheel(wheels[0]), verify_sdist(sdists[0])]
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
