# SPDX-License-Identifier: Apache-2.0
"""Low-level OpenTelemetry-to-Evidence bridge contracts.

The separate ``meridian-storage-plugin-observability`` package owns public
tracers, meters, loggers, and process-wide provider installation.  This module
only preserves OTel fields, creates Evidence Expressions, and supplies bounded
non-recursive buffering for that plugin and other integrations.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime
from queue import Empty, Full, Queue
from threading import Lock

from meridian_storage import Expression, ResourceRef

from .canonical import bounded_string, sha256_fingerprint
from .catalogs import EvidenceCatalogSurface
from .errors import EvidenceQueueExhausted, InvalidEvidenceDefinition, InvalidEvidenceRecord
from .policy import QueueFailurePolicy
from .records import (
    EvidenceMetadata,
    LogRecord,
    MetricPoint,
    MetricTemporality,
    SpanRecord,
    deterministic_evidence_id,
)

type OTelRecord = LogRecord | SpanRecord | MetricPoint


@dataclass(frozen=True, slots=True)
class OTelBridgeHealth:
    """Bounded, non-recursive bridge counters suitable for a health sink."""

    accepted: int
    exported: int
    dropped: int
    suppressed: int
    exhausted: int
    queue_depth: int
    queue_capacity: int

    def to_dict(self) -> dict[str, int]:
        return {
            "accepted": self.accepted,
            "exported": self.exported,
            "dropped": self.dropped,
            "suppressed": self.suppressed,
            "exhausted": self.exhausted,
            "queueDepth": self.queue_depth,
            "queueCapacity": self.queue_capacity,
        }


class OTelEvidenceBridge:
    """Translate and buffer OTel signal Data as Evidence append Expressions."""

    def __init__(
        self,
        *,
        resource: ResourceRef | str,
        capacity: int = 2048,
        failure_policy: QueueFailurePolicy = QueueFailurePolicy.DROP,
        enqueue_timeout_seconds: float = 0.25,
    ) -> None:
        if (
            isinstance(capacity, bool)
            or not isinstance(capacity, int)
            or not 1 <= capacity <= 1_000_000
        ):
            raise InvalidEvidenceDefinition(
                "capacity must be between 1 and 1000000",
                requirement="evidence.otel.queue",
            )
        if (
            isinstance(enqueue_timeout_seconds, bool)
            or not isinstance(enqueue_timeout_seconds, (int, float))
            or not 0 <= enqueue_timeout_seconds <= 30
        ):
            raise InvalidEvidenceDefinition(
                "enqueue_timeout_seconds must be between 0 and 30",
                requirement="evidence.otel.queue",
            )
        if not isinstance(failure_policy, QueueFailurePolicy):
            try:
                failure_policy = QueueFailurePolicy(failure_policy)
            except ValueError as exc:
                raise InvalidEvidenceDefinition(
                    "invalid OTel queue failure policy",
                    requirement="evidence.otel.queue",
                ) from exc
        try:
            self._resource = ResourceRef.parse(resource, catalog="evidence")
        except (TypeError, ValueError) as exc:
            raise InvalidEvidenceDefinition(
                "the OTel bridge requires a logical Evidence Resource",
                requirement="evidence.otel.resource",
            ) from exc
        self._queue: Queue[Expression] = Queue(maxsize=capacity)
        self._failure_policy = failure_policy
        self._timeout = float(enqueue_timeout_seconds)
        self._surface = EvidenceCatalogSurface()
        self._suppression: ContextVar[int] = ContextVar(
            f"meridian_evidence_otel_suppression_{id(self)}", default=0
        )
        self._counter_lock = Lock()
        self._accepted = 0
        self._exported = 0
        self._dropped = 0
        self._suppressed = 0
        self._exhausted = 0

    @property
    def resource(self) -> ResourceRef:
        return self._resource

    @contextmanager
    def suppress_instrumentation(self) -> Iterator[None]:
        """Prevent exporter and health-sink activity from instrumenting itself."""

        token = self._suppression.set(self._suppression.get() + 1)
        try:
            yield
        finally:
            self._suppression.reset(token)

    @contextmanager
    def export_batch(self, *, limit: int = 512) -> Iterator[tuple[Expression, ...]]:
        """Drain a batch while recursion suppression stays active for execution."""

        with self.suppress_instrumentation():
            yield self.drain(limit=limit)

    def offer(self, record: OTelRecord) -> bool:
        """Offer one OTel record according to the configured bounded policy."""

        if not isinstance(record, (LogRecord, SpanRecord, MetricPoint)):
            raise InvalidEvidenceDefinition(
                "the OTel bridge accepts only log, span, and metric-point records",
                requirement="evidence.otel.signal",
            )
        if self._suppression.get() > 0:
            self._increment("suppressed")
            return False
        identity = deterministic_evidence_id(record)
        expression = self._surface.append(
            resource=self._resource,
            data=record,
            idempotency_key=identity,
        )
        try:
            if self._failure_policy is QueueFailurePolicy.BLOCK:
                self._queue.put(expression, block=True, timeout=self._timeout)
            else:
                self._queue.put_nowait(expression)
        except Full as exc:
            self._increment("exhausted")
            if self._failure_policy is QueueFailurePolicy.DROP:
                self._increment("dropped")
                return False
            raise EvidenceQueueExhausted() from exc
        self._increment("accepted")
        return True

    def drain(self, *, limit: int = 512) -> tuple[Expression, ...]:
        """Return up to ``limit`` queued Expressions in insertion order."""

        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10_000:
            raise InvalidEvidenceDefinition(
                "drain limit must be between 1 and 10000",
                requirement="evidence.otel.queue",
            )
        result: list[Expression] = []
        for _ in range(limit):
            try:
                result.append(self._queue.get_nowait())
            except Empty:
                break
        if result:
            with self._counter_lock:
                self._exported += len(result)
        return tuple(result)

    def health(self) -> OTelBridgeHealth:
        """Read health state without producing another telemetry signal."""

        with self._counter_lock:
            return OTelBridgeHealth(
                accepted=self._accepted,
                exported=self._exported,
                dropped=self._dropped,
                suppressed=self._suppressed,
                exhausted=self._exhausted,
                queue_depth=self._queue.qsize(),
                queue_capacity=self._queue.maxsize,
            )

    def log(
        self,
        *,
        severity: str,
        body: object,
        event_time: datetime | str,
        observed_time: datetime | str,
        otel_resource: Mapping[str, object],
        instrumentation_scope: Mapping[str, object],
        attributes: Mapping[str, object] | None = None,
        flags: int = 0,
        trace_id: str | None = None,
        span_id: str | None = None,
        tenant: str | None = None,
        scope: Mapping[str, str] | None = None,
        ingestion_identity: str | None = None,
        source_protocol_version: str = "OTLP/1.0",
        provenance: Mapping[str, str] | None = None,
    ) -> bool:
        """Preserve one OTel log record and offer it to the bounded queue."""

        return self.offer(
            LogRecord(
                severity=severity,
                body=body,
                flags=flags,
                trace_id=trace_id,
                span_id=span_id,
                metadata=_metadata(
                    event_time=event_time,
                    observed_time=observed_time,
                    otel_resource=otel_resource,
                    instrumentation_scope=instrumentation_scope,
                    attributes=attributes,
                    tenant=tenant,
                    scope=scope,
                    ingestion_identity=ingestion_identity,
                    source_protocol_version=source_protocol_version,
                    provenance=provenance,
                ),
            )
        )

    def span(
        self,
        *,
        trace_id: str,
        span_id: str,
        name: str,
        span_kind: str,
        start_time: datetime | str,
        end_time: datetime | str,
        status: str,
        observed_time: datetime | str,
        otel_resource: Mapping[str, object],
        instrumentation_scope: Mapping[str, object],
        attributes: Mapping[str, object] | None = None,
        parent_span_id: str | None = None,
        events: Sequence[Mapping[str, object]] = (),
        links: Sequence[Mapping[str, object]] = (),
        tenant: str | None = None,
        scope: Mapping[str, str] | None = None,
        ingestion_identity: str | None = None,
        source_protocol_version: str = "OTLP/1.0",
        provenance: Mapping[str, str] | None = None,
    ) -> bool:
        """Preserve one OTel span, including parent, events, and links."""

        return self.offer(
            SpanRecord(
                trace_id=trace_id,
                span_id=span_id,
                parent_span_id=parent_span_id,
                name=name,
                span_kind=span_kind,
                start_time=start_time,
                end_time=end_time,
                status=status,
                events=events,
                links=links,
                metadata=_metadata(
                    event_time=end_time,
                    observed_time=observed_time,
                    otel_resource=otel_resource,
                    instrumentation_scope=instrumentation_scope,
                    attributes=attributes,
                    tenant=tenant,
                    scope=scope,
                    ingestion_identity=ingestion_identity,
                    source_protocol_version=source_protocol_version,
                    provenance=provenance,
                ),
            )
        )

    def metric_point(
        self,
        *,
        name: str,
        unit: str,
        metric_type: str,
        temporality: MetricTemporality,
        monotonic: bool,
        start_time: datetime | str,
        end_time: datetime | str,
        value: object,
        observed_time: datetime | str,
        otel_resource: Mapping[str, object],
        instrumentation_scope: Mapping[str, object],
        dimensions: Mapping[str, object] | None = None,
        attributes: Mapping[str, object] | None = None,
        flags: int = 0,
        exemplars: Sequence[Mapping[str, object]] = (),
        tenant: str | None = None,
        scope: Mapping[str, str] | None = None,
        ingestion_identity: str | None = None,
        source_protocol_version: str = "OTLP/1.0",
        provenance: Mapping[str, str] | None = None,
    ) -> bool:
        """Preserve one OTel metric point, temporality, flags, and exemplars."""

        return self.offer(
            MetricPoint(
                name=name,
                unit=unit,
                metric_type=metric_type,
                temporality=temporality,
                monotonic=monotonic,
                start_time=start_time,
                end_time=end_time,
                value=value,
                dimensions=dimensions or {},
                flags=flags,
                exemplars=exemplars,
                metadata=_metadata(
                    event_time=end_time,
                    observed_time=observed_time,
                    otel_resource=otel_resource,
                    instrumentation_scope=instrumentation_scope,
                    attributes=attributes,
                    tenant=tenant,
                    scope=scope,
                    ingestion_identity=ingestion_identity,
                    source_protocol_version=source_protocol_version,
                    provenance=provenance,
                ),
            )
        )

    def _increment(self, counter: str) -> None:
        with self._counter_lock:
            if counter == "accepted":
                self._accepted += 1
            elif counter == "dropped":
                self._dropped += 1
            elif counter == "suppressed":
                self._suppressed += 1
            elif counter == "exhausted":
                self._exhausted += 1
            else:
                raise AssertionError(f"unknown bridge counter {counter!r}")


def _metadata(
    *,
    event_time: datetime | str,
    observed_time: datetime | str,
    otel_resource: Mapping[str, object],
    instrumentation_scope: Mapping[str, object],
    attributes: Mapping[str, object] | None,
    tenant: str | None,
    scope: Mapping[str, str] | None,
    ingestion_identity: str | None,
    source_protocol_version: str,
    provenance: Mapping[str, str] | None,
) -> EvidenceMetadata:
    try:
        protocol = bounded_string(source_protocol_version, "source protocol version", 128)
    except ValueError as exc:
        raise InvalidEvidenceRecord(str(exc), requirement="record.sourceProtocolVersion") from exc
    identity = sha256_fingerprint(
        {
            "eventTime": str(event_time),
            "otelResource": dict(otel_resource),
            "instrumentationScope": dict(instrumentation_scope),
            "tenant": tenant,
            "scope": dict(scope or {}),
            "protocol": protocol,
        }
    )
    return EvidenceMetadata(
        event_time=event_time,
        observed_time=observed_time,
        tenant=tenant,
        scope=scope or {},
        otel_resource=otel_resource,
        instrumentation_scope=instrumentation_scope,
        ingestion_identity=ingestion_identity or identity,
        source_protocol_version=protocol,
        attributes=attributes or {},
        provenance=provenance or {},
    )


__all__ = ["OTelBridgeHealth", "OTelEvidenceBridge", "OTelRecord"]
