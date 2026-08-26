# SPDX-License-Identifier: Apache-2.0
"""Verify checked-in Evidence contracts and print deterministic evidence."""

from __future__ import annotations

import hashlib
import json
import sys
import tomllib
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

import meridian_storage.evidence as evidence

ROOT = Path(__file__).resolve().parents[1]


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return cast(dict[str, Any], value)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_spdx() -> None:
    code_files = [
        *ROOT.glob("src/**/*.py"),
        *ROOT.glob("tests/**/*.py"),
        *ROOT.glob("scripts/*.py"),
        *ROOT.glob(".github/**/*.yml"),
        ROOT / "pyproject.toml",
    ]
    for path in code_files:
        assert "SPDX-License-Identifier: Apache-2.0" in path.read_text(encoding="utf-8")[:256]
    markdown_files = [
        *ROOT.glob("*.md"),
        *ROOT.glob("docs/*.md"),
    ]
    for path in markdown_files:
        assert path.read_text(encoding="utf-8").startswith(
            "<!-- SPDX-License-Identifier: Apache-2.0 -->"
        )
    for path in [ROOT / "compatibility.json", *ROOT.glob("contracts/**/*.json")]:
        assert load_json(path).get("$comment") == "SPDX-License-Identifier: Apache-2.0"
    assert (ROOT / "LICENSE").is_file()
    assert (ROOT / "NOTICE").is_file()
    assert not (ROOT / "src" / "meridian_storage" / "__init__.py").exists()


def main() -> int:
    verify_spdx()
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    assert project["name"] == "meridian-storage-evidence"
    assert project["version"] == evidence.__version__ == "1.0.0"
    assert project["license"] == "Apache-2.0"
    assert project["dependencies"] == [
        "meridian-storage-core==1.0.0",
        "meridian-storage-semantics==1.0.0",
    ]
    entry_points = project["entry-points"]
    assert entry_points["meridian_storage.catalogs"]["evidence"].endswith(
        ":EvidenceCatalogProvider"
    )
    assert entry_points["meridian_storage.schemas"]["evidence"].endswith(":EvidenceSchemaProvider")

    public_path = ROOT / "contracts" / "public-api" / "meridian-evidence.v1.json"
    public = load_json(public_path)
    assert public["exports"] == sorted(evidence.__all__)
    assert public["errorCodes"] == list(evidence.EVIDENCE_ERROR_CODES)
    assert all(hasattr(evidence, name) for name in public["exports"])

    catalog_path = ROOT / "contracts" / "catalogs" / "meridian-evidence-catalog.v1.json"
    catalog = load_json(catalog_path)
    catalog.pop("$comment")
    assert catalog == evidence.evidence_manifest().to_dict()

    compatibility_path = ROOT / "compatibility.json"
    compatibility = load_json(compatibility_path)
    assert compatibility["version"] == evidence.__version__
    assert compatibility["design"] == {
        "hldRevision": 60,
        "catalogsAndPublicInterfacesRevision": 72,
        "evidenceSection": "5.7",
    }
    assert compatibility["contracts"]["methods"] == [
        "append",
        "create_resource",
        "publish_schema",
        "query",
    ]
    assert compatibility["boundaries"]["implementsWorm"] is False
    assert compatibility["boundaries"]["implementsNationalSecurityProfile"] is False

    schemas = {name: evidence.evidence_schema(name) for name in evidence.schema_names()}
    registry = Registry().with_resources(
        (cast(str, schema["$id"]), Resource.from_contents(schema)) for schema in schemas.values()
    )
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
    golden_hashes: dict[str, str] = {}
    for path in sorted((ROOT / "contracts" / "conformance" / "golden").glob("*.json")):
        fixture = load_json(path)
        schema_name = cast(str, fixture["schema"])
        Draft202012Validator(schemas[schema_name], registry=registry).validate(fixture["record"])
        golden_hashes[path.name] = sha256(path)

    bundle = evidence.EvidenceSchemaProvider().load()
    result = {
        "catalogManifestFingerprint": evidence.evidence_manifest().fingerprint,
        "catalogLedgerSha256": sha256(catalog_path),
        "compatibilityLedgerSha256": sha256(compatibility_path),
        "errorCodeCount": len(evidence.EVIDENCE_ERROR_CODES),
        "goldenFixtureSha256": golden_hashes,
        "package": "meridian-storage-evidence",
        "publicApiLedgerSha256": sha256(public_path),
        "publicExportCount": len(evidence.__all__),
        "schemaBundleFingerprint": bundle.fingerprint,
        "schemaCount": len(schemas),
        "version": evidence.__version__,
    }
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
