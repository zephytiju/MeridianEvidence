# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from meridian_storage import OperationResult, ResourceRef
from meridian_storage.evidence import (
    EvidenceCatalogProvider,
    EvidenceProfile,
    EvidenceQuery,
    EvidenceQueryResult,
    InvalidEvidenceDefinition,
    QueryDirection,
    QueryOrder,
)
from tests.support import FINGERPRINT_1, FINGERPRINT_2, FINGERPRINT_3


def test_query_normalization_and_fingerprint_are_engine_neutral() -> None:
    where = {"severity": {"eq": "INFO"}, "tenant": {"eq": "tenant-a"}}
    query = EvidenceQuery(
        "runtime.logs",
        where=where,
        select=("eventTime", "body"),
        order_by=(QueryOrder("eventTime", QueryDirection.DESCENDING),),
        limit=25,
        cursor="opaque-cursor",
        profile=EvidenceProfile.TELEMETRY,
    )
    where["severity"] = {"eq": "DEBUG"}
    operation = EvidenceCatalogProvider().normalize(query.expression())
    assert operation.resources == (ResourceRef("evidence", "runtime", "logs"),)
    assert operation.input["where"]["severity"] == {"eq": "INFO"}  # type: ignore[index]
    assert operation.input["orderBy"] == ({"direction": "desc", "field": "eventTime"},)
    assert query.fingerprint.startswith("sha256:")
    assert query.to_dict()["profile"] == "telemetry"


def test_query_result_preserves_core_provenance() -> None:
    result = OperationResult(
        data={"items": [{"body": "ready"}], "nextCursor": "next"},
        catalog="evidence",
        operation_contract="meridian.evidence.query",
        operation_version="1.0.0",
        resources=(ResourceRef("evidence", "runtime", "logs"),),
        request_id="request-1",
        execution_id="execution-1",
        operation_fingerprint=FINGERPRINT_1,
        registry_fingerprint=FINGERPRINT_2,
        capability_fingerprint=FINGERPRINT_3,
        provenance={"adapter": "conformance"},
    )
    normalized = EvidenceQueryResult.from_operation_result(result)
    assert normalized.data == {"items": [{"body": "ready"}], "nextCursor": "next"}
    assert normalized.provenance == {"adapter": "conformance"}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"resource": "bad"},
        {"resource": "runtime.logs", "where": []},
        {"resource": "runtime.logs", "select": ("bad field",)},
        {"resource": "runtime.logs", "select": ("body", "body")},
        {"resource": "runtime.logs", "order_by": ({"field": "body"},)},
        {"resource": "runtime.logs", "order_by": ({"field": "body", "direction": "sideways"},)},
        {"resource": "runtime.logs", "limit": 0},
        {"resource": "runtime.logs", "cursor": "x" * 5000},
        {"resource": "runtime.logs", "profile": "other"},
    ],
)
def test_query_rejects_nonportable_inputs(kwargs: dict[str, object]) -> None:
    with pytest.raises(InvalidEvidenceDefinition):
        EvidenceQuery(**kwargs)  # type: ignore[arg-type]


def test_query_result_rejects_wrong_contract() -> None:
    result = OperationResult(
        data=[],
        catalog="evidence",
        operation_contract="meridian.evidence.append",
        operation_version="1.0.0",
        resources=(ResourceRef("evidence", "runtime", "logs"),),
        request_id="request-1",
        execution_id="execution-1",
        operation_fingerprint=FINGERPRINT_1,
        registry_fingerprint=FINGERPRINT_2,
        capability_fingerprint=FINGERPRINT_3,
    )
    with pytest.raises(InvalidEvidenceDefinition, match="query result"):
        EvidenceQueryResult.from_operation_result(result)
