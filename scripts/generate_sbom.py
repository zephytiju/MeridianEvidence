# SPDX-License-Identifier: Apache-2.0
"""Generate a deterministic SPDX 2.3 JSON SBOM for release artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: generate_sbom.py DIST_DIRECTORY OUTPUT_FILE")
    directory = Path(sys.argv[1])
    output = Path(sys.argv[2])
    artifacts = sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and (path.suffix == ".whl" or path.name.endswith(".tar.gz"))
    )
    if not artifacts:
        raise AssertionError("no Python artifacts found for SBOM generation")
    artifact_hashes = {path.name: digest(path) for path in artifacts}
    aggregate = hashlib.sha256(
        json.dumps(artifact_hashes, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    created = datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    files: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []
    for index, path in enumerate(artifacts, start=1):
        spdx_id = f"SPDXRef-Artifact-{index}"
        files.append(
            {
                "SPDXID": spdx_id,
                "checksums": [{"algorithm": "SHA256", "checksumValue": artifact_hashes[path.name]}],
                "copyrightText": "NOASSERTION",
                "fileName": path.name,
                "licenseConcluded": "Apache-2.0",
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package-Evidence",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": spdx_id,
            }
        )
    document: dict[str, Any] = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: meridian-storage-evidence/generate_sbom.py-1.0.0"],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": f"https://spdx.meridian.dev/evidence/1.0.0/{aggregate}",
        "files": files,
        "name": "meridian-storage-evidence-1.0.0",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-Evidence",
                "copyrightText": "Copyright 2026 Meridian contributors",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": "Apache-2.0",
                "licenseDeclared": "Apache-2.0",
                "name": "meridian-storage-evidence",
                "supplier": "Organization: Meridian contributors",
                "versionInfo": "1.0.0",
            },
            {
                "SPDXID": "SPDXRef-Package-Core",
                "copyrightText": "NOASSERTION",
                "downloadLocation": "https://pypi.org/project/meridian-storage-core/1.0.0/",
                "filesAnalyzed": False,
                "licenseConcluded": "Apache-2.0",
                "licenseDeclared": "Apache-2.0",
                "name": "meridian-storage-core",
                "versionInfo": "1.0.0",
            },
            {
                "SPDXID": "SPDXRef-Package-Semantics",
                "copyrightText": "NOASSERTION",
                "downloadLocation": "https://pypi.org/project/meridian-storage-semantics/1.0.0/",
                "filesAnalyzed": False,
                "licenseConcluded": "Apache-2.0",
                "licenseDeclared": "Apache-2.0",
                "name": "meridian-storage-semantics",
                "versionInfo": "1.0.0",
            },
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package-Evidence",
            },
            {
                "spdxElementId": "SPDXRef-Package-Evidence",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": "SPDXRef-Package-Core",
            },
            {
                "spdxElementId": "SPDXRef-Package-Evidence",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": "SPDXRef-Package-Semantics",
            },
            *relationships,
        ],
        "spdxVersion": "SPDX-2.3",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"output": str(output), "sha256": digest(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
