# SPDX-License-Identifier: Apache-2.0
"""Compare installed Evidence normalization with the released 1.0.0 baseline.

Run with Python -I and pass the fixture path, so no checkout imports are available.
"""

from __future__ import annotations

import json
import sys
from importlib.metadata import version
from pathlib import Path

from meridian_storage import Expression
from meridian_storage.evidence import EvidenceCatalogProvider, InvalidEvidenceDefinition


def snapshot() -> dict[str, object]:
    provider = EvidenceCatalogProvider()
    surface = provider.create_surface()
    expressions = {
        "scalar": surface.append(resource="runtime.logs", data={"body": "ready"}),
        "batch": surface.append(
            resource="runtime.logs", data=[{"evidenceId": "a"}, {"evidenceId": "b"}]
        ),
        "atomic": surface.append(
            resource="audit.actions", data={"action": "write"}, require_atomic=True
        ),
        "query": surface.query(resource="runtime.logs", where={"severity": {"eq": "INFO"}}),
    }
    operations = {}
    for name, expression in expressions.items():
        operation = provider.normalize(expression)
        operations[name] = {
            "value": operation.to_dict(),
            "fingerprint": operation.request_fingerprint,
        }
    try:
        provider.normalize(Expression("evidence", "delete", {}))
    except InvalidEvidenceDefinition as exc:
        error = exc.to_dict()
    else:
        raise AssertionError("unsupported operation accepted")
    return {"operations": operations, "error": error}


def main() -> None:
    actual = snapshot()
    expected = json.loads(Path(sys.argv[1]).read_text())
    assert actual == expected["snapshot"], "installed Evidence contract drifted from 1.0.0"
    versions = {
        name: version(name)
        for name in (
            "meridian-storage-evidence",
            "meridian-storage-core",
            "meridian-storage-semantics",
        )
    }
    assert tuple(versions.values()) == ("1.0.2", "1.1.0", "2.0.1")
    print(json.dumps({"installedVersions": versions, "baselineMatched": True}, sort_keys=True))


if __name__ == "__main__":
    main()
