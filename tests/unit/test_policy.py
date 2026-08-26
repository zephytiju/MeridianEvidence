# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from meridian_storage.evidence import (
    AtomicityPolicy,
    CardinalityBudget,
    EvidenceErrorCode,
    EvidencePolicy,
    EvidencePolicyViolation,
    EvidenceScopeViolation,
    InvalidEvidenceDefinition,
    QueueFailurePolicy,
    RedactionRule,
    RedactionStrategy,
    RetentionPolicyInput,
)


def test_retention_is_logical_policy_input_only() -> None:
    retention = RetentionPolicyInput(
        "audit-standard",
        classification="internal",
        minimum_days=30,
        maximum_days=365,
        disposition="review",
        extensions={"future.worm/profile": "optional"},
    )
    assert retention.to_dict() == {
        "label": "audit-standard",
        "classification": "internal",
        "minimumDays": 30,
        "maximumDays": 365,
        "disposition": "review",
        "extensions": {"future.worm/profile": "optional"},
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        {"minimum_days": -1},
        {"minimum_days": 5, "maximum_days": 4},
        {"disposition": "delete-now"},
    ],
)
def test_retention_rejects_invalid_inputs(kwargs: dict[str, object]) -> None:
    with pytest.raises(InvalidEvidenceDefinition):
        RetentionPolicyInput("retention", **kwargs)  # type: ignore[arg-type]


def test_policy_redacts_drops_and_preserves_input() -> None:
    source = {
        "profile": "audit",
        "attributes": {"password": "secret", "token": "secret", "safe": "yes"},
    }
    policy = EvidencePolicy(
        "audit-safe",
        required_fields=("profile", "attributes.safe"),
        redaction_rules=(
            RedactionRule("attributes.password", RedactionStrategy.REDACT),
            RedactionRule("attributes.token", RedactionStrategy.DROP),
        ),
        atomicity=AtomicityPolicy.REQUIRED,
        access_scopes=("audit:read",),
        retention=RetentionPolicyInput("audit", minimum_days=30),
        queue_failure=QueueFailurePolicy.FAIL,
    )
    decision = policy.apply(source)
    assert decision.data["attributes"] == {"password": "[REDACTED]", "safe": "yes"}
    assert decision.redacted_paths == ("attributes.password",)
    assert decision.dropped_paths == ("attributes.token",)
    assert source["attributes"]["password"] == "secret"
    assert policy.requires_atomicity
    assert policy.to_dict()["retention"]["minimumDays"] == 30  # type: ignore[index]
    policy.require_access_scope("audit:read")
    with pytest.raises(EvidenceScopeViolation) as caught:
        policy.require_access_scope("audit:write")
    assert caught.value.to_dict()["policyLabel"] == "audit-safe"


def test_policy_rejects_required_sensitive_and_bounded_values() -> None:
    with pytest.raises(EvidencePolicyViolation, match="missing"):
        EvidencePolicy("required", required_fields=("tenant",)).apply({"profile": "audit"})
    with pytest.raises(EvidencePolicyViolation, match="prohibited"):
        EvidencePolicy(
            "reject",
            redaction_rules=(RedactionRule("attributes.secret", RedactionStrategy.REJECT),),
        ).apply({"attributes": {"secret": "x"}})
    with pytest.raises(EvidencePolicyViolation) as cardinality:
        EvidencePolicy("small", maximum_attributes=1).apply({"attributes": {"a": 1, "b": 2}})
    assert cardinality.value.code == EvidenceErrorCode.CARDINALITY_LIMIT
    with pytest.raises(EvidencePolicyViolation, match="value bound"):
        EvidencePolicy("small-value", maximum_attribute_value_bytes=2).apply(
            {"attributes": {"a": "long"}}
        )
    with pytest.raises(EvidencePolicyViolation, match="record exceeds"):
        EvidencePolicy("small-record", maximum_record_bytes=10).apply({"body": "long-value"})


def test_cardinality_tracker_is_deterministic_and_bounded() -> None:
    tracker = CardinalityBudget(2, policy_label="telemetry")
    tracker.observe("evidence:runtime.metrics", {"worker": "a"})
    tracker.observe("evidence:runtime.metrics", {"worker": "a"})
    tracker.observe("evidence:runtime.metrics", {"worker": "b"})
    assert tracker.snapshot() == {"observed": 2, "maximum": 2}
    with pytest.raises(EvidencePolicyViolation) as caught:
        tracker.observe("evidence:runtime.metrics", {"worker": "c"})
    assert caught.value.code == EvidenceErrorCode.CARDINALITY_LIMIT
    assert EvidencePolicy("telemetry", cardinality_budget=2).cardinality_tracker().maximum == 2


def test_policy_definition_validation() -> None:
    with pytest.raises(InvalidEvidenceDefinition, match="redaction path"):
        RedactionRule("bad path", RedactionStrategy.DROP)
    with pytest.raises(InvalidEvidenceDefinition, match="strategy"):
        RedactionRule("attributes.value", "unknown")  # type: ignore[arg-type]
    with pytest.raises(InvalidEvidenceDefinition, match="meaningful"):
        RedactionRule("attributes.value", RedactionStrategy.DROP, replacement="x")
    with pytest.raises(InvalidEvidenceDefinition, match="unique"):
        EvidencePolicy(
            "duplicate",
            redaction_rules=(
                RedactionRule("attributes.value", RedactionStrategy.DROP),
                RedactionRule("attributes.value", RedactionStrategy.REDACT),
            ),
        )
    with pytest.raises(InvalidEvidenceDefinition, match="between"):
        EvidencePolicy("bad", maximum_attributes=0)
    with pytest.raises(InvalidEvidenceDefinition, match="dotted"):
        EvidencePolicy("bad", required_fields=("bad path",))
    with pytest.raises(InvalidEvidenceDefinition, match="retention"):
        EvidencePolicy("bad", retention="30d")  # type: ignore[arg-type]
    with pytest.raises(InvalidEvidenceDefinition, match="positive"):
        CardinalityBudget(0, policy_label="bad")
