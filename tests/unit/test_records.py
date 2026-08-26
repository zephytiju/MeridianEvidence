# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from meridian_storage.evidence import (
    AuditOutcome,
    AuditRecord,
    Correlation,
    EvidenceMetadata,
    EvidenceReference,
    InvalidEvidenceRecord,
    LineageRecord,
    LineageStatus,
    LogRecord,
    MetricPoint,
    MetricTemporality,
    ProvenanceRecord,
    SpanRecord,
    deterministic_evidence_id,
    record_mapping,
)

NOW = datetime(2026, 8, 25, 12, tzinfo=UTC)
FP = "sha256:" + "a" * 64


def metadata() -> EvidenceMetadata:
    return EvidenceMetadata(
        evidence_id="evidence-1",
        event_time=NOW,
        observed_time="2026-08-25T12:00:01Z",
        tenant="tenant-a",
        scope={"z": "2", "a": "1"},
        otel_resource={"service.name": "worker"},
        instrumentation_scope={"name": "test"},
        ingestion_identity="ingest-1",
        source_protocol_version="OTLP/1.0",
        attributes={"count": 1},
        provenance={"adapter": "test"},
        subject=EvidenceReference("resource", "structured:cases.open"),
        correlation=Correlation(
            trace_id="0" * 32,
            span_id="1" * 16,
            request_id="request-1",
            operation_fingerprint=FP,
        ),
        extensions={"example.test/version": "1"},
    )


def test_log_record_preserves_common_and_trace_fields() -> None:
    body = {"items": [1]}
    record = LogRecord(
        "INFO", body, flags=1, trace_id="0" * 32, span_id="1" * 16, metadata=metadata()
    )
    body["items"].append(2)
    value = record.to_dict()
    assert value["body"] == {"items": [1]}
    assert value["scope"] == {"a": "1", "z": "2"}
    assert value["eventTime"] == "2026-08-25T12:00:00.000000Z"
    assert value["traceId"] == "0" * 32
    assert deterministic_evidence_id(record) == deterministic_evidence_id(value)


def test_span_record_preserves_relationships_and_interval() -> None:
    record = SpanRecord(
        trace_id="0" * 32,
        span_id="1" * 16,
        parent_span_id="2" * 16,
        name="work",
        span_kind="internal",
        start_time=NOW,
        end_time="2026-08-25T12:00:01Z",
        status="ok",
        events=({"name": "started"},),
        links=({"traceId": "3" * 32, "spanId": "4" * 16},),
        metadata=metadata(),
    )
    value = record.to_dict()
    assert value["parentSpanId"] == "2" * 16
    assert value["events"] == [{"name": "started"}]
    with pytest.raises(InvalidEvidenceRecord, match="precede"):
        SpanRecord("0" * 32, "1" * 16, "bad", "internal", NOW, "2026-08-25T11:00:00Z", "ok")


def test_metric_point_accepts_numeric_and_histogram_values() -> None:
    point = MetricPoint(
        name="duration",
        unit="ms",
        metric_type="histogram",
        temporality=MetricTemporality.DELTA,
        monotonic=False,
        start_time=NOW,
        end_time=NOW,
        value={"count": 1, "sum": 2.0},
        dimensions={"worker": "a"},
        exemplars=({"value": 2.0},),
    )
    assert point.to_dict()["temporality"] == "delta"
    assert point.to_dict()["value"] == {"count": 1, "sum": 2.0}
    numeric = MetricPoint("count", "1", "sum", "cumulative", True, NOW, NOW, 2)
    assert numeric.temporality is MetricTemporality.CUMULATIVE


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"temporality": "bad"}, "temporality"),
        ({"monotonic": 1}, "monotonic"),
        ({"value": "bad"}, "numeric"),
        ({"flags": -1}, "flags"),
        ({"end_time": "2026-08-25T11:00:00Z"}, "precede"),
    ],
)
def test_metric_rejects_invalid_fields(kwargs: dict[str, object], message: str) -> None:
    values: dict[str, object] = {
        "name": "count",
        "unit": "1",
        "metric_type": "sum",
        "temporality": MetricTemporality.DELTA,
        "monotonic": True,
        "start_time": NOW,
        "end_time": NOW,
        "value": 1,
    }
    values.update(kwargs)
    with pytest.raises(InvalidEvidenceRecord, match=message):
        MetricPoint(**values)  # type: ignore[arg-type]


def test_audit_rejects_bodies_and_serializes_correction() -> None:
    record = AuditRecord(
        action="case.updated",
        outcome="success",
        actor=EvidenceReference("principal", "principal:user-1"),
        changes={"fieldCount": 2},
        policy_labels=("z", "a", "z"),
        correction_of=EvidenceReference("audit", "audit-1"),
        binding_provenance={"binding": "logical-a"},
        metadata=metadata(),
    )
    assert record.outcome is AuditOutcome.SUCCESS
    assert record.to_dict()["policyLabels"] == ["a", "z"]
    assert record.to_dict()["correctionOf"] == {"kind": "audit", "value": "audit-1"}
    with pytest.raises(InvalidEvidenceRecord, match="unrestricted"):
        AuditRecord("case.updated", AuditOutcome.SUCCESS, changes={"requestBody": {"x": 1}})


def test_lineage_checkpoint_is_idempotent_and_canonical() -> None:
    a = EvidenceReference("resource", "structured:z.rows")
    b = EvidenceReference("resource", "structured:a.rows")
    record = LineageRecord(
        activity="model.train",
        status="checkpoint",
        execution_id="execution-1",
        inputs=(a, b, a),
        outputs=(b,),
        query_fingerprints=(FP, FP),
        checkpoint_key="epoch-1",
        metadata_values={"epoch": 1},
        metadata=metadata(),
    )
    assert record.status is LineageStatus.CHECKPOINT
    assert record.to_dict()["inputs"] == [b.to_dict(), a.to_dict()]
    assert record.to_dict()["queryFingerprints"] == [FP]
    with pytest.raises(InvalidEvidenceRecord, match="checkpoint_key"):
        LineageRecord("train", LineageStatus.CHECKPOINT, "execution-1")


def test_provenance_requires_sources_and_sorts_them() -> None:
    entity = EvidenceReference("artifact", "object:models.release", digest=FP)
    a = EvidenceReference("resource", "structured:z.rows")
    b = EvidenceReference("resource", "structured:a.rows")
    record = ProvenanceRecord(entity, (a, b, a), actor=EvidenceReference("principal", "p"))
    assert record.to_dict()["sources"] == [b.to_dict(), a.to_dict()]
    with pytest.raises(InvalidEvidenceRecord, match="at least one"):
        ProvenanceRecord(entity, ())


def test_record_and_metadata_validation() -> None:
    with pytest.raises(InvalidEvidenceRecord, match="trace_id"):
        Correlation(trace_id="bad")
    with pytest.raises(InvalidEvidenceRecord, match="span_id"):
        Correlation(span_id="bad")
    with pytest.raises(InvalidEvidenceRecord, match="subject"):
        EvidenceMetadata(subject="bad")  # type: ignore[arg-type]
    with pytest.raises(InvalidEvidenceRecord, match="correlation"):
        EvidenceMetadata(correlation="bad")  # type: ignore[arg-type]
    with pytest.raises(InvalidEvidenceRecord, match="flags"):
        LogRecord("INFO", "body", flags=-1)
    with pytest.raises(InvalidEvidenceRecord, match="empty"):
        record_mapping({})
