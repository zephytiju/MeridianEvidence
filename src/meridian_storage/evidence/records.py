# SPDX-License-Identifier: Apache-2.0
"""Immutable provider-neutral Evidence record helpers."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol, cast, runtime_checkable

from .canonical import (
    JsonValue,
    bounded_string,
    canonical_mapping,
    canonical_value,
    fingerprint,
    optional_string,
    sha256_fingerprint,
    utc_timestamp,
)
from .errors import InvalidEvidenceRecord

EVIDENCE_DATA_FORMAT_VERSION = "meridian-evidence-data.v1"
_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")


class EvidenceProfile(StrEnum):
    TELEMETRY = "telemetry"
    AUDIT = "audit"
    LINEAGE = "lineage"
    PROVENANCE = "provenance"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    UNKNOWN = "unknown"


class LineageStatus(StrEnum):
    STARTED = "started"
    CHECKPOINT = "checkpoint"
    COMPLETED = "completed"
    FAILED = "failed"


class MetricTemporality(StrEnum):
    UNSPECIFIED = "unspecified"
    DELTA = "delta"
    CUMULATIVE = "cumulative"


def _record_string(value: object, field_name: str, maximum: int = 512) -> str:
    try:
        return bounded_string(value, field_name, maximum)
    except ValueError as exc:
        raise InvalidEvidenceRecord(str(exc), requirement=f"record.{field_name}") from exc


def _record_optional_string(value: object, field_name: str, maximum: int = 512) -> str | None:
    try:
        return optional_string(value, field_name, maximum)
    except ValueError as exc:
        raise InvalidEvidenceRecord(str(exc), requirement=f"record.{field_name}") from exc


def _record_fingerprint(value: object, field_name: str) -> str:
    try:
        return fingerprint(value, field_name)
    except ValueError as exc:
        raise InvalidEvidenceRecord(str(exc), requirement=f"record.{field_name}") from exc


def _safe_mapping(
    value: Mapping[str, object], field_name: str, maximum_entries: int = 128
) -> Mapping[str, JsonValue]:
    try:
        return canonical_mapping(value, field_name=field_name, maximum_entries=maximum_entries)
    except (TypeError, ValueError) as exc:
        raise InvalidEvidenceRecord(str(exc), requirement=f"record.{field_name}") from exc


def _safe_strings(
    value: Mapping[str, str], field_name: str, maximum_entries: int = 64
) -> Mapping[str, str]:
    if not isinstance(value, Mapping) or len(value) > maximum_entries:
        raise InvalidEvidenceRecord(
            f"{field_name} must contain at most {maximum_entries} entries",
            requirement=f"record.{field_name}",
        )
    result = {
        _record_string(key, f"{field_name} key", 128): _record_string(
            item, f"{field_name} value", 512
        )
        for key, item in value.items()
    }
    return dict(sorted(result.items()))


def _stored_mapping(value: Mapping[str, object]) -> dict[str, JsonValue]:
    """Expose a defensive JSON mapping after constructor validation."""

    return cast(dict[str, JsonValue], dict(value))


@dataclass(frozen=True, slots=True, order=True)
class EvidenceReference:
    """Logical reference to a Resource, Data value, Operation, Schema, or artifact."""

    kind: str
    value: str
    version: str | None = None
    digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _record_string(self.kind, "reference kind", 64))
        object.__setattr__(self, "value", _record_string(self.value, "reference value", 1024))
        object.__setattr__(
            self, "version", _record_optional_string(self.version, "reference version", 256)
        )
        if self.digest is not None:
            object.__setattr__(self, "digest", _record_fingerprint(self.digest, "reference digest"))

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            key: value
            for key, value in {
                "kind": self.kind,
                "value": self.value,
                "version": self.version,
                "digest": self.digest,
            }.items()
            if value is not None
        }


@dataclass(frozen=True, slots=True)
class Correlation:
    trace_id: str | None = None
    span_id: str | None = None
    request_id: str | None = None
    execution_id: str | None = None
    operation_fingerprint: str | None = None
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        if self.trace_id is not None and _TRACE_ID_RE.fullmatch(self.trace_id) is None:
            raise InvalidEvidenceRecord(
                "trace_id must be 32 lowercase hexadecimal characters",
                requirement="record.correlation.trace-id",
            )
        if self.span_id is not None and _SPAN_ID_RE.fullmatch(self.span_id) is None:
            raise InvalidEvidenceRecord(
                "span_id must be 16 lowercase hexadecimal characters",
                requirement="record.correlation.span-id",
            )
        for name in ("request_id", "execution_id", "correlation_id"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _record_string(value, name, 256))
        if self.operation_fingerprint is not None:
            object.__setattr__(
                self,
                "operation_fingerprint",
                _record_fingerprint(self.operation_fingerprint, "operation fingerprint"),
            )

    def to_dict(self) -> dict[str, JsonValue]:
        values = {
            "traceId": self.trace_id,
            "spanId": self.span_id,
            "requestId": self.request_id,
            "executionId": self.execution_id,
            "operationFingerprint": self.operation_fingerprint,
            "correlationId": self.correlation_id,
        }
        return {key: value for key, value in values.items() if value is not None}


@dataclass(frozen=True, slots=True)
class EvidenceMetadata:
    """Common context carried by stored Evidence Data after enrichment."""

    evidence_id: str | None = None
    event_time: datetime | str | None = None
    observed_time: datetime | str | None = None
    tenant: str | None = None
    scope: Mapping[str, str] = field(default_factory=dict)
    otel_resource: Mapping[str, object] = field(default_factory=dict)
    instrumentation_scope: Mapping[str, object] = field(default_factory=dict)
    ingestion_identity: str | None = None
    source_protocol_version: str | None = None
    attributes: Mapping[str, object] = field(default_factory=dict)
    provenance: Mapping[str, str] = field(default_factory=dict)
    subject: EvidenceReference | None = None
    correlation: Correlation | None = None
    extensions: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name, maximum in (
            ("evidence_id", 256),
            ("tenant", 256),
            ("ingestion_identity", 256),
            ("source_protocol_version", 128),
        ):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _record_string(value, name, maximum))
        for name in ("event_time", "observed_time"):
            value = getattr(self, name)
            if value is not None:
                try:
                    object.__setattr__(self, name, utc_timestamp(value, name))
                except (TypeError, ValueError) as exc:
                    raise InvalidEvidenceRecord(str(exc), requirement=f"record.{name}") from exc
        object.__setattr__(self, "scope", _safe_strings(self.scope, "scope", 32))
        object.__setattr__(self, "otel_resource", _safe_mapping(self.otel_resource, "otelResource"))
        object.__setattr__(
            self,
            "instrumentation_scope",
            _safe_mapping(self.instrumentation_scope, "instrumentationScope"),
        )
        object.__setattr__(self, "attributes", _safe_mapping(self.attributes, "attributes"))
        object.__setattr__(self, "provenance", _safe_strings(self.provenance, "provenance"))
        object.__setattr__(self, "extensions", _safe_mapping(self.extensions, "extensions"))
        if self.subject is not None and not isinstance(self.subject, EvidenceReference):
            raise InvalidEvidenceRecord(
                "subject must be an EvidenceReference", requirement="record.subject"
            )
        if self.correlation is not None and not isinstance(self.correlation, Correlation):
            raise InvalidEvidenceRecord(
                "correlation must be a Correlation", requirement="record.correlation"
            )

    def envelope(self, profile: EvidenceProfile, kind: str) -> dict[str, JsonValue]:
        values: dict[str, JsonValue] = {
            "formatVersion": EVIDENCE_DATA_FORMAT_VERSION,
            "profile": profile.value,
            "kind": _record_string(kind, "record kind", 64),
            "scope": dict(self.scope),
            "otelResource": _stored_mapping(self.otel_resource),
            "instrumentationScope": _stored_mapping(self.instrumentation_scope),
            "attributes": _stored_mapping(self.attributes),
            "provenance": dict(self.provenance),
            "extensions": _stored_mapping(self.extensions),
        }
        optional: dict[str, JsonValue | None] = {
            "evidenceId": self.evidence_id,
            "eventTime": cast(str | None, self.event_time),
            "observedTime": cast(str | None, self.observed_time),
            "tenant": self.tenant,
            "ingestionIdentity": self.ingestion_identity,
            "sourceProtocolVersion": self.source_protocol_version,
            "subject": None if self.subject is None else self.subject.to_dict(),
            "correlation": None if self.correlation is None else self.correlation.to_dict(),
        }
        values.update({key: value for key, value in optional.items() if value is not None})
        return values


@runtime_checkable
class EvidenceRecord(Protocol):
    @property
    def profile(self) -> EvidenceProfile: ...

    @property
    def kind(self) -> str: ...

    def to_dict(self) -> dict[str, JsonValue]: ...


@dataclass(frozen=True, slots=True)
class LogRecord:
    severity: str
    body: object
    flags: int = 0
    trace_id: str | None = None
    span_id: str | None = None
    metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)

    profile = EvidenceProfile.TELEMETRY
    kind = "log"

    def __post_init__(self) -> None:
        object.__setattr__(self, "severity", _record_string(self.severity, "severity", 32))
        try:
            object.__setattr__(self, "body", canonical_value(self.body, field_name="body"))
        except (TypeError, ValueError) as exc:
            raise InvalidEvidenceRecord(str(exc), requirement="record.log.body") from exc
        if isinstance(self.flags, bool) or not isinstance(self.flags, int) or self.flags < 0:
            raise InvalidEvidenceRecord(
                "flags must be a non-negative integer", requirement="record.log.flags"
            )
        Correlation(trace_id=self.trace_id, span_id=self.span_id)

    def to_dict(self) -> dict[str, JsonValue]:
        result = self.metadata.envelope(self.profile, self.kind)
        result.update(
            {"severity": self.severity, "body": cast(JsonValue, self.body), "flags": self.flags}
        )
        if self.trace_id is not None:
            result["traceId"] = self.trace_id
        if self.span_id is not None:
            result["spanId"] = self.span_id
        return result


@dataclass(frozen=True, slots=True)
class SpanRecord:
    trace_id: str
    span_id: str
    name: str
    span_kind: str
    start_time: datetime | str
    end_time: datetime | str
    status: str
    parent_span_id: str | None = None
    events: Sequence[Mapping[str, object]] = ()
    links: Sequence[Mapping[str, object]] = ()
    metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)

    profile = EvidenceProfile.TELEMETRY
    kind = "span"

    def __post_init__(self) -> None:
        Correlation(trace_id=self.trace_id, span_id=self.span_id)
        if self.parent_span_id is not None:
            Correlation(span_id=self.parent_span_id)
        for name in ("name", "span_kind", "status"):
            object.__setattr__(self, name, _record_string(getattr(self, name), name, 256))
        try:
            start = utc_timestamp(self.start_time, "start_time")
            end = utc_timestamp(self.end_time, "end_time")
        except (TypeError, ValueError) as exc:
            raise InvalidEvidenceRecord(str(exc), requirement="record.span.interval") from exc
        if end < start:
            raise InvalidEvidenceRecord(
                "span end_time must not precede start_time", requirement="record.span.interval"
            )
        object.__setattr__(self, "start_time", start)
        object.__setattr__(self, "end_time", end)
        object.__setattr__(
            self,
            "events",
            tuple(_safe_mapping(item, "span event") for item in self.events),
        )
        object.__setattr__(
            self,
            "links",
            tuple(_safe_mapping(item, "span link") for item in self.links),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        result = self.metadata.envelope(self.profile, self.kind)
        result.update(
            {
                "traceId": self.trace_id,
                "spanId": self.span_id,
                "name": self.name,
                "spanKind": self.span_kind,
                "startTime": cast(str, self.start_time),
                "endTime": cast(str, self.end_time),
                "status": self.status,
                "events": [_stored_mapping(item) for item in self.events],
                "links": [_stored_mapping(item) for item in self.links],
            }
        )
        if self.parent_span_id is not None:
            result["parentSpanId"] = self.parent_span_id
        return result


@dataclass(frozen=True, slots=True)
class MetricPoint:
    name: str
    unit: str
    metric_type: str
    temporality: MetricTemporality
    monotonic: bool
    start_time: datetime | str
    end_time: datetime | str
    value: object
    dimensions: Mapping[str, object] = field(default_factory=dict)
    flags: int = 0
    exemplars: Sequence[Mapping[str, object]] = ()
    metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)

    profile = EvidenceProfile.TELEMETRY
    kind = "metric-point"

    def __post_init__(self) -> None:
        for name in ("name", "unit", "metric_type"):
            object.__setattr__(self, name, _record_string(getattr(self, name), name, 256))
        if not isinstance(self.temporality, MetricTemporality):
            try:
                object.__setattr__(self, "temporality", MetricTemporality(self.temporality))
            except (TypeError, ValueError) as exc:
                raise InvalidEvidenceRecord(
                    "invalid metric temporality", requirement="record.metric.temporality"
                ) from exc
        if not isinstance(self.monotonic, bool):
            raise InvalidEvidenceRecord(
                "monotonic must be boolean", requirement="record.metric.monotonic"
            )
        try:
            start = utc_timestamp(self.start_time, "start_time")
            end = utc_timestamp(self.end_time, "end_time")
            point = canonical_value(self.value, field_name="metric value")
        except (TypeError, ValueError) as exc:
            raise InvalidEvidenceRecord(str(exc), requirement="record.metric.value") from exc
        if end < start:
            raise InvalidEvidenceRecord(
                "metric end_time must not precede start_time",
                requirement="record.metric.interval",
            )
        if not isinstance(point, (int, float, dict)) or isinstance(point, bool):
            raise InvalidEvidenceRecord(
                "metric value must be numeric or a histogram object",
                requirement="record.metric.value",
            )
        object.__setattr__(self, "start_time", start)
        object.__setattr__(self, "end_time", end)
        object.__setattr__(self, "value", point)
        object.__setattr__(self, "dimensions", _safe_mapping(self.dimensions, "dimensions"))
        object.__setattr__(
            self,
            "exemplars",
            tuple(_safe_mapping(item, "metric exemplar") for item in self.exemplars),
        )
        if isinstance(self.flags, bool) or not isinstance(self.flags, int) or self.flags < 0:
            raise InvalidEvidenceRecord(
                "flags must be a non-negative integer", requirement="record.metric.flags"
            )

    def to_dict(self) -> dict[str, JsonValue]:
        result = self.metadata.envelope(self.profile, self.kind)
        result.update(
            {
                "name": self.name,
                "unit": self.unit,
                "metricType": self.metric_type,
                "temporality": self.temporality.value,
                "monotonic": self.monotonic,
                "startTime": cast(str, self.start_time),
                "endTime": cast(str, self.end_time),
                "value": cast(JsonValue, self.value),
                "dimensions": _stored_mapping(self.dimensions),
                "flags": self.flags,
                "exemplars": [_stored_mapping(item) for item in self.exemplars],
            }
        )
        return result


_UNRESTRICTED_BODY_KEYS = frozenset(
    {"request", "response", "requestBody", "responseBody", "request_body", "response_body"}
)


@dataclass(frozen=True, slots=True)
class AuditRecord:
    action: str
    outcome: AuditOutcome
    actor: EvidenceReference | None = None
    request_id: str | None = None
    operation: EvidenceReference | None = None
    changes: Mapping[str, object] = field(default_factory=dict)
    policy_labels: Sequence[str] = ()
    correction_of: EvidenceReference | None = None
    binding_provenance: Mapping[str, str] = field(default_factory=dict)
    metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)

    profile = EvidenceProfile.AUDIT
    kind = "action"

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", _record_string(self.action, "audit action", 256))
        if not isinstance(self.outcome, AuditOutcome):
            try:
                object.__setattr__(self, "outcome", AuditOutcome(self.outcome))
            except (TypeError, ValueError) as exc:
                raise InvalidEvidenceRecord(
                    "invalid audit outcome", requirement="record.audit.outcome"
                ) from exc
        for name in ("actor", "operation", "correction_of"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, EvidenceReference):
                raise InvalidEvidenceRecord(
                    f"{name} must be an EvidenceReference",
                    requirement=f"record.audit.{name}",
                )
        object.__setattr__(
            self, "request_id", _record_optional_string(self.request_id, "request_id", 256)
        )
        unsafe = _UNRESTRICTED_BODY_KEYS.intersection(self.changes)
        if unsafe:
            raise InvalidEvidenceRecord(
                "audit changes must not contain unrestricted request or response bodies",
                requirement="record.audit.safe-change-metadata",
            )
        object.__setattr__(self, "changes", _safe_mapping(self.changes, "changes"))
        object.__setattr__(
            self,
            "policy_labels",
            tuple(
                sorted({_record_string(item, "policy label", 256) for item in self.policy_labels})
            ),
        )
        object.__setattr__(
            self,
            "binding_provenance",
            _safe_strings(self.binding_provenance, "bindingProvenance"),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        result = self.metadata.envelope(self.profile, self.kind)
        result.update(
            {
                "action": self.action,
                "outcome": self.outcome.value,
                "changes": _stored_mapping(self.changes),
                "policyLabels": list(self.policy_labels),
                "bindingProvenance": dict(self.binding_provenance),
            }
        )
        optional: dict[str, JsonValue | None] = {
            "actor": None if self.actor is None else self.actor.to_dict(),
            "requestId": self.request_id,
            "operation": None if self.operation is None else self.operation.to_dict(),
            "correctionOf": None if self.correction_of is None else self.correction_of.to_dict(),
        }
        result.update({key: value for key, value in optional.items() if value is not None})
        return result


@dataclass(frozen=True, slots=True)
class LineageRecord:
    activity: str
    status: LineageStatus
    execution_id: str
    inputs: Sequence[EvidenceReference] = ()
    outputs: Sequence[EvidenceReference] = ()
    schema_versions: Mapping[str, str] = field(default_factory=dict)
    model_versions: Mapping[str, str] = field(default_factory=dict)
    query_fingerprints: Sequence[str] = ()
    source_revisions: Mapping[str, str] = field(default_factory=dict)
    transformation_digest: str | None = None
    artifact_digest: str | None = None
    actor: EvidenceReference | None = None
    checkpoint_key: str | None = None
    context_scope: Mapping[str, str] = field(default_factory=dict)
    metadata_values: Mapping[str, object] = field(default_factory=dict)
    metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)

    profile = EvidenceProfile.LINEAGE
    kind = "activity"

    def __post_init__(self) -> None:
        object.__setattr__(self, "activity", _record_string(self.activity, "activity", 256))
        object.__setattr__(
            self, "execution_id", _record_string(self.execution_id, "execution_id", 256)
        )
        if not isinstance(self.status, LineageStatus):
            try:
                object.__setattr__(self, "status", LineageStatus(self.status))
            except (TypeError, ValueError) as exc:
                raise InvalidEvidenceRecord(
                    "invalid lineage status", requirement="record.lineage.status"
                ) from exc
        for name in ("inputs", "outputs"):
            values = tuple(getattr(self, name))
            if any(not isinstance(item, EvidenceReference) for item in values):
                raise InvalidEvidenceRecord(
                    f"{name} must contain EvidenceReference values",
                    requirement=f"record.lineage.{name}",
                )
            object.__setattr__(self, name, tuple(sorted(set(values))))
        for name in ("schema_versions", "model_versions", "source_revisions", "context_scope"):
            object.__setattr__(self, name, _safe_strings(getattr(self, name), name))
        object.__setattr__(
            self,
            "query_fingerprints",
            tuple(
                sorted(
                    {
                        _record_fingerprint(item, "query fingerprint")
                        for item in self.query_fingerprints
                    }
                )
            ),
        )
        for name in ("transformation_digest", "artifact_digest"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _record_fingerprint(value, name))
        if self.actor is not None and not isinstance(self.actor, EvidenceReference):
            raise InvalidEvidenceRecord(
                "actor must be an EvidenceReference", requirement="record.lineage.actor"
            )
        object.__setattr__(
            self,
            "checkpoint_key",
            _record_optional_string(self.checkpoint_key, "checkpoint_key", 256),
        )
        if self.status is LineageStatus.CHECKPOINT and self.checkpoint_key is None:
            raise InvalidEvidenceRecord(
                "checkpoint lineage requires checkpoint_key",
                requirement="record.lineage.checkpoint",
            )
        object.__setattr__(self, "metadata_values", _safe_mapping(self.metadata_values, "metadata"))

    def to_dict(self) -> dict[str, JsonValue]:
        result = self.metadata.envelope(self.profile, self.kind)
        result.update(
            {
                "activity": self.activity,
                "status": self.status.value,
                "executionId": self.execution_id,
                "inputs": [item.to_dict() for item in self.inputs],
                "outputs": [item.to_dict() for item in self.outputs],
                "schemaVersions": dict(self.schema_versions),
                "modelVersions": dict(self.model_versions),
                "queryFingerprints": list(self.query_fingerprints),
                "sourceRevisions": dict(self.source_revisions),
                "contextScope": dict(self.context_scope),
                "metadata": _stored_mapping(self.metadata_values),
            }
        )
        optional: dict[str, JsonValue | None] = {
            "transformationDigest": self.transformation_digest,
            "artifactDigest": self.artifact_digest,
            "actor": None if self.actor is None else self.actor.to_dict(),
            "checkpointKey": self.checkpoint_key,
        }
        result.update({key: value for key, value in optional.items() if value is not None})
        return result


@dataclass(frozen=True, slots=True)
class ProvenanceRecord:
    entity: EvidenceReference
    sources: Sequence[EvidenceReference]
    generated_by: EvidenceReference | None = None
    actor: EvidenceReference | None = None
    metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)

    profile = EvidenceProfile.PROVENANCE
    kind = "provenance"

    def __post_init__(self) -> None:
        if not isinstance(self.entity, EvidenceReference):
            raise InvalidEvidenceRecord(
                "entity must be an EvidenceReference", requirement="record.provenance.entity"
            )
        values = tuple(self.sources)
        if not values or any(not isinstance(item, EvidenceReference) for item in values):
            raise InvalidEvidenceRecord(
                "sources must contain at least one EvidenceReference",
                requirement="record.provenance.sources",
            )
        object.__setattr__(self, "sources", tuple(sorted(set(values))))
        for name in ("generated_by", "actor"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, EvidenceReference):
                raise InvalidEvidenceRecord(
                    f"{name} must be an EvidenceReference",
                    requirement=f"record.provenance.{name}",
                )

    def to_dict(self) -> dict[str, JsonValue]:
        result = self.metadata.envelope(self.profile, self.kind)
        result.update(
            {
                "entity": self.entity.to_dict(),
                "sources": [item.to_dict() for item in self.sources],
            }
        )
        if self.generated_by is not None:
            result["generatedBy"] = self.generated_by.to_dict()
        if self.actor is not None:
            result["actor"] = self.actor.to_dict()
        return result


def record_mapping(value: Mapping[str, object] | EvidenceRecord) -> dict[str, JsonValue]:
    """Normalize a mapping-first or typed Evidence record without mutating input."""

    try:
        result = value.to_dict() if isinstance(value, EvidenceRecord) else canonical_mapping(value)
    except (TypeError, ValueError) as exc:
        if isinstance(exc, InvalidEvidenceRecord):
            raise
        raise InvalidEvidenceRecord(str(exc), requirement="record.mapping") from exc
    if not result:
        raise InvalidEvidenceRecord(
            "evidence record must not be empty", requirement="record.mapping"
        )
    return result


def deterministic_evidence_id(value: Mapping[str, object] | EvidenceRecord) -> str:
    return sha256_fingerprint(record_mapping(value))


__all__ = [
    "EVIDENCE_DATA_FORMAT_VERSION",
    "AuditOutcome",
    "AuditRecord",
    "Correlation",
    "EvidenceMetadata",
    "EvidenceProfile",
    "EvidenceRecord",
    "EvidenceReference",
    "LineageRecord",
    "LineageStatus",
    "LogRecord",
    "MetricPoint",
    "MetricTemporality",
    "ProvenanceRecord",
    "SpanRecord",
    "deterministic_evidence_id",
    "record_mapping",
]
