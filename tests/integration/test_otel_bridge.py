# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from meridian_storage.evidence import (
    EvidenceCatalogProvider,
    EvidenceQueueExhausted,
    InvalidEvidenceDefinition,
    LogRecord,
    MetricTemporality,
    OTelEvidenceBridge,
    QueueFailurePolicy,
)

NOW = datetime(2026, 8, 25, 12, tzinfo=UTC)
RESOURCE = {"service.name": "worker", "service.version": "1.0.0"}
SCOPE = {"name": "example.worker", "version": "1.0.0"}


def test_log_span_and_metric_field_fidelity() -> None:
    bridge = OTelEvidenceBridge(resource="runtime.signals", capacity=3)
    assert bridge.log(
        severity="INFO",
        body={"message": "ready"},
        event_time=NOW,
        observed_time=NOW,
        otel_resource=RESOURCE,
        instrumentation_scope=SCOPE,
        attributes={"worker": "alpha", "attempt": 1},
        flags=1,
        trace_id="0" * 32,
        span_id="1" * 16,
        tenant="tenant-a",
        scope={"environment": "test"},
    )
    assert bridge.span(
        trace_id="0" * 32,
        span_id="1" * 16,
        parent_span_id="2" * 16,
        name="work.poll",
        span_kind="internal",
        start_time=NOW,
        end_time=NOW,
        status="ok",
        observed_time=NOW,
        otel_resource=RESOURCE,
        instrumentation_scope=SCOPE,
        events=({"name": "received"},),
        links=({"traceId": "3" * 32, "spanId": "4" * 16},),
    )
    assert bridge.metric_point(
        name="work.duration",
        unit="ms",
        metric_type="histogram",
        temporality=MetricTemporality.DELTA,
        monotonic=False,
        start_time=NOW,
        end_time=NOW,
        value={"count": 1, "sum": 2.0},
        observed_time=NOW,
        otel_resource=RESOURCE,
        instrumentation_scope=SCOPE,
        dimensions={"worker": "alpha"},
        flags=2,
        exemplars=({"traceId": "0" * 32, "spanId": "1" * 16, "value": 2.0},),
    )
    expressions = bridge.drain(limit=3)
    assert [item.arguments["data"]["kind"] for item in expressions] == [  # type: ignore[index]
        "log",
        "span",
        "metric-point",
    ]
    log = expressions[0].arguments["data"]
    span = expressions[1].arguments["data"]
    metric = expressions[2].arguments["data"]
    assert log["otelResource"] == RESOURCE  # type: ignore[index]
    assert log["instrumentationScope"] == SCOPE  # type: ignore[index]
    assert log["sourceProtocolVersion"] == "OTLP/1.0"  # type: ignore[index]
    assert span["parentSpanId"] == "2" * 16  # type: ignore[index]
    assert metric["temporality"] == "delta"  # type: ignore[index]
    assert metric["exemplars"][0]["value"] == 2.0  # type: ignore[index]
    assert all(EvidenceCatalogProvider().normalize(item).idempotent for item in expressions)


def test_recursion_suppression_and_non_recursive_health() -> None:
    bridge = OTelEvidenceBridge(resource="runtime.logs", capacity=1)
    record = LogRecord("INFO", "ready")
    with bridge.suppress_instrumentation():
        assert bridge.offer(record) is False
    assert bridge.offer(record) is True
    with bridge.export_batch(limit=1) as batch:
        assert len(batch) == 1
        assert bridge.offer(record) is False
    assert bridge.health().to_dict() == {
        "accepted": 1,
        "exported": 1,
        "dropped": 0,
        "suppressed": 2,
        "exhausted": 0,
        "queueDepth": 0,
        "queueCapacity": 1,
    }


@pytest.mark.parametrize("policy", [QueueFailurePolicy.FAIL, QueueFailurePolicy.BLOCK])
def test_queue_exhaustion_can_fail_with_retryable_error(policy: QueueFailurePolicy) -> None:
    bridge = OTelEvidenceBridge(
        resource="runtime.logs",
        capacity=1,
        failure_policy=policy,
        enqueue_timeout_seconds=0,
    )
    assert bridge.offer(LogRecord("INFO", "first"))
    with pytest.raises(EvidenceQueueExhausted) as caught:
        bridge.offer(LogRecord("INFO", "second"))
    assert caught.value.retryable is True
    assert bridge.health().exhausted == 1


def test_queue_exhaustion_can_drop() -> None:
    bridge = OTelEvidenceBridge(resource="runtime.logs", capacity=1)
    assert bridge.offer(LogRecord("INFO", "first"))
    assert bridge.offer(LogRecord("INFO", "second")) is False
    assert bridge.health().dropped == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {"capacity": 0},
        {"capacity": True},
        {"enqueue_timeout_seconds": -1},
        {"failure_policy": "unknown"},
    ],
)
def test_bridge_configuration_is_bounded(kwargs: dict[str, object]) -> None:
    with pytest.raises(InvalidEvidenceDefinition):
        OTelEvidenceBridge(resource="runtime.logs", **kwargs)  # type: ignore[arg-type]


def test_bridge_rejects_wrong_signals_and_drain_limit() -> None:
    bridge = OTelEvidenceBridge(resource="runtime.logs")
    with pytest.raises(Exception, match="only log"):
        bridge.offer(object())  # type: ignore[arg-type]
    with pytest.raises(InvalidEvidenceDefinition, match="drain limit"):
        bridge.drain(limit=0)
