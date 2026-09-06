# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path

import meridian_storage.evidence as evidence
from meridian_storage.evidence import EVIDENCE_ERROR_CODES, evidence_manifest

ROOT = Path(__file__).resolve().parents[2]


def _json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def test_public_api_and_error_code_ledgers_are_exact() -> None:
    ledger = _json(ROOT / "contracts" / "public-api" / "meridian-evidence.v1.json")
    assert sorted(evidence.__all__) == ledger["exports"]  # type: ignore[index]
    assert list(EVIDENCE_ERROR_CODES) == ledger["errorCodes"]  # type: ignore[index]
    assert all(hasattr(evidence, name) for name in ledger["exports"])  # type: ignore[index]


def test_catalog_manifest_ledger_is_exact() -> None:
    ledger = _json(ROOT / "contracts" / "catalogs" / "meridian-evidence-catalog.v1.json")
    ledger.pop("$comment")
    assert evidence_manifest().to_dict() == ledger


def test_compatibility_ledger_pins_released_dependencies_and_boundaries() -> None:
    ledger = _json(ROOT / "compatibility.json")
    assert ledger["version"] == evidence.__version__  # type: ignore[index]
    assert [item["constraint"] for item in ledger["dependencies"]] == [  # type: ignore[index]
        "==1.0.1",
        "==2.0.0",
    ]
    assert ledger["design"] == {  # type: ignore[index]
        "hldRevision": 60,
        "catalogsAndPublicInterfacesRevision": 72,
        "evidenceSection": "5.7",
    }
    boundaries = ledger["boundaries"]  # type: ignore[index]
    assert boundaries["implementsWorm"] is False
    assert boundaries["implementsNationalSecurityProfile"] is False
    assert boundaries["observabilityFacadeOwner"] == "meridian-storage-plugin-observability"
