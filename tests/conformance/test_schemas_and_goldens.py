# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from meridian_storage.evidence import (
    AuditOutcome,
    AuditRecord,
    Correlation,
    EvidenceMetadata,
    EvidenceReference,
    EvidenceSchemaProvider,
    InvalidEvidenceRecord,
    LineageRecord,
    LineageStatus,
    LogRecord,
    MetricPoint,
    MetricTemporality,
    ProvenanceRecord,
    SpanRecord,
    evidence_schema,
    schema_names,
)

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "contracts" / "conformance" / "golden"


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _registry() -> tuple[dict[str, Mapping[str, object]], Registry]:
    schemas = {name: cast(Mapping[str, object], evidence_schema(name)) for name in schema_names()}
    registry = Registry().with_resources(
        (cast(str, schema["$id"]), Resource.from_contents(schema)) for schema in schemas.values()
    )
    return schemas, registry


@pytest.mark.conformance
def test_every_schema_is_valid_draft_2020_12_and_every_golden_conforms() -> None:
    schemas, registry = _registry()
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
    for path in sorted(GOLDEN.glob("*.json")):
        fixture = _load(path)
        schema_name = cast(str, fixture["schema"])
        record = cast(Mapping[str, object], fixture["record"])
        Draft202012Validator(schemas[schema_name], registry=registry).validate(record)


def _metadata(record: Mapping[str, object]) -> EvidenceMetadata:
    correlation_value = record.get("correlation")
    correlation = None
    if isinstance(correlation_value, Mapping):
        correlation = Correlation(
            trace_id=cast(str | None, correlation_value.get("traceId")),
            span_id=cast(str | None, correlation_value.get("spanId")),
            request_id=cast(str | None, correlation_value.get("requestId")),
            execution_id=cast(str | None, correlation_value.get("executionId")),
            operation_fingerprint=cast(str | None, correlation_value.get("operationFingerprint")),
            correlation_id=cast(str | None, correlation_value.get("correlationId")),
        )
    subject_value = record.get("subject")
    return EvidenceMetadata(
        evidence_id=cast(str | None, record.get("evidenceId")),
        event_time=cast(str | None, record.get("eventTime")),
        observed_time=cast(str | None, record.get("observedTime")),
        tenant=cast(str | None, record.get("tenant")),
        scope=cast(Mapping[str, str], record.get("scope", {})),
        otel_resource=cast(Mapping[str, object], record.get("otelResource", {})),
        instrumentation_scope=cast(Mapping[str, object], record.get("instrumentationScope", {})),
        ingestion_identity=cast(str | None, record.get("ingestionIdentity")),
        source_protocol_version=cast(str | None, record.get("sourceProtocolVersion")),
        attributes=cast(Mapping[str, object], record.get("attributes", {})),
        provenance=cast(Mapping[str, str], record.get("provenance", {})),
        subject=None
        if subject_value is None
        else _reference(cast(Mapping[str, object], subject_value)),
        correlation=correlation,
        extensions=cast(Mapping[str, object], record.get("extensions", {})),
    )


def _reference(value: Mapping[str, object]) -> EvidenceReference:
    return EvidenceReference(
        kind=cast(str, value["kind"]),
        value=cast(str, value["value"]),
        version=cast(str | None, value.get("version")),
        digest=cast(str | None, value.get("digest")),
    )


def _references(values: object) -> tuple[EvidenceReference, ...]:
    return tuple(
        _reference(cast(Mapping[str, object], item)) for item in cast(list[object], values)
    )


def _model(schema: str, record: Mapping[str, object]) -> object:
    common = _metadata(record)
    if schema == "log":
        return LogRecord(
            severity=cast(str, record["severity"]),
            body=record["body"],
            flags=cast(int, record["flags"]),
            trace_id=cast(str | None, record.get("traceId")),
            span_id=cast(str | None, record.get("spanId")),
            metadata=common,
        )
    if schema == "span":
        return SpanRecord(
            trace_id=cast(str, record["traceId"]),
            span_id=cast(str, record["spanId"]),
            parent_span_id=cast(str | None, record.get("parentSpanId")),
            name=cast(str, record["name"]),
            span_kind=cast(str, record["spanKind"]),
            start_time=cast(str, record["startTime"]),
            end_time=cast(str, record["endTime"]),
            status=cast(str, record["status"]),
            events=cast(list[Mapping[str, object]], record["events"]),
            links=cast(list[Mapping[str, object]], record["links"]),
            metadata=common,
        )
    if schema == "metric_point":
        return MetricPoint(
            name=cast(str, record["name"]),
            unit=cast(str, record["unit"]),
            metric_type=cast(str, record["metricType"]),
            temporality=MetricTemporality(cast(str, record["temporality"])),
            monotonic=cast(bool, record["monotonic"]),
            start_time=cast(str, record["startTime"]),
            end_time=cast(str, record["endTime"]),
            value=record["value"],
            dimensions=cast(Mapping[str, object], record["dimensions"]),
            flags=cast(int, record["flags"]),
            exemplars=cast(list[Mapping[str, object]], record["exemplars"]),
            metadata=common,
        )
    if schema == "audit":
        return AuditRecord(
            action=cast(str, record["action"]),
            outcome=AuditOutcome(cast(str, record["outcome"])),
            actor=_reference(cast(Mapping[str, object], record["actor"])),
            request_id=cast(str, record["requestId"]),
            operation=_reference(cast(Mapping[str, object], record["operation"])),
            changes=cast(Mapping[str, object], record["changes"]),
            policy_labels=cast(list[str], record["policyLabels"]),
            correction_of=_reference(cast(Mapping[str, object], record["correctionOf"])),
            binding_provenance=cast(Mapping[str, str], record["bindingProvenance"]),
            metadata=common,
        )
    if schema == "lineage":
        return LineageRecord(
            activity=cast(str, record["activity"]),
            status=LineageStatus(cast(str, record["status"])),
            execution_id=cast(str, record["executionId"]),
            inputs=_references(record["inputs"]),
            outputs=_references(record["outputs"]),
            schema_versions=cast(Mapping[str, str], record["schemaVersions"]),
            model_versions=cast(Mapping[str, str], record["modelVersions"]),
            query_fingerprints=cast(list[str], record["queryFingerprints"]),
            source_revisions=cast(Mapping[str, str], record["sourceRevisions"]),
            transformation_digest=cast(str, record["transformationDigest"]),
            artifact_digest=cast(str, record["artifactDigest"]),
            actor=_reference(cast(Mapping[str, object], record["actor"])),
            checkpoint_key=cast(str, record["checkpointKey"]),
            context_scope=cast(Mapping[str, str], record["contextScope"]),
            metadata_values=cast(Mapping[str, object], record["metadata"]),
            metadata=common,
        )
    if schema == "provenance":
        return ProvenanceRecord(
            entity=_reference(cast(Mapping[str, object], record["entity"])),
            sources=_references(record["sources"]),
            generated_by=_reference(cast(Mapping[str, object], record["generatedBy"])),
            actor=_reference(cast(Mapping[str, object], record["actor"])),
            metadata=common,
        )
    raise AssertionError(schema)


@pytest.mark.conformance
def test_typed_records_round_trip_golden_values_exactly() -> None:
    for path in sorted(GOLDEN.glob("*.json")):
        fixture = _load(path)
        schema = cast(str, fixture["schema"])
        record = cast(Mapping[str, object], fixture["record"])
        assert _model(schema, record).to_dict() == record  # type: ignore[attr-defined]


@pytest.mark.conformance
def test_invalid_fixtures_fail_with_expected_requirements() -> None:
    fixture = _load(ROOT / "contracts" / "conformance" / "invalid" / "invalid-records.json")
    cases = cast(list[Mapping[str, object]], fixture["cases"])
    for case in cases:
        data = cast(Mapping[str, object], case["data"])
        with pytest.raises(InvalidEvidenceRecord) as caught:
            schema = case["schema"]
            if schema == "audit":
                AuditRecord(
                    cast(str, data["action"]),
                    AuditOutcome(cast(str, data["outcome"])),
                    changes=cast(Mapping[str, object], data["changes"]),
                )
            elif schema == "lineage":
                LineageRecord(
                    cast(str, data["activity"]),
                    LineageStatus(cast(str, data["status"])),
                    cast(str, data["executionId"]),
                )
            elif schema == "log":
                LogRecord(
                    cast(str, data["severity"]),
                    data["body"],
                    trace_id=cast(str, data["traceId"]),
                )
            else:
                MetricPoint(
                    cast(str, data["name"]),
                    cast(str, data["unit"]),
                    cast(str, data["metricType"]),
                    cast(MetricTemporality, data["temporality"]),
                    False,
                    "2026-08-25T12:00:00Z",
                    "2026-08-25T12:00:00Z",
                    1,
                )
        assert caught.value.to_dict()["requirement"] == case["expectedRequirement"]


def test_schema_provider_bundle_is_deterministic_and_complete() -> None:
    first = EvidenceSchemaProvider().load()
    second = EvidenceSchemaProvider().load()
    assert first.fingerprint == second.fingerprint
    assert len(first.schemas) == len(schema_names()) == 9
    assert first.resources[0].ref.canonical == "evidence:meridian.registry"
    assert first.resources[0].required_scope == ("tenant",)
    assert first.extensions["design.catalogRevision"] == 72


def test_unknown_schema_is_rejected() -> None:
    with pytest.raises(KeyError, match="unknown Evidence schema"):
        evidence_schema("missing")
