# SPDX-License-Identifier: Apache-2.0
"""Provider-neutral Evidence policy and retention inputs."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from threading import Lock
from typing import cast

from .canonical import (
    JsonValue,
    bounded_string,
    canonical_json,
    canonical_mapping,
    sha256_fingerprint,
)
from .errors import (
    EvidenceErrorCode,
    EvidencePolicyViolation,
    EvidenceScopeViolation,
    InvalidEvidenceDefinition,
)

_PATH_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z][A-Za-z0-9_-]*)*$")


class RedactionStrategy(StrEnum):
    REJECT = "reject"
    REDACT = "redact"
    DROP = "drop"


class AtomicityPolicy(StrEnum):
    BEST_EFFORT = "best-effort"
    REQUIRED = "required"


class QueueFailurePolicy(StrEnum):
    DROP = "drop"
    BLOCK = "block"
    FAIL = "fail"


def _definition_error(message: str) -> InvalidEvidenceDefinition:
    return InvalidEvidenceDefinition(message, requirement="evidence.policy.definition")


def _definition_string(value: object, field_name: str, maximum: int = 512) -> str:
    try:
        return bounded_string(value, field_name, maximum)
    except ValueError as exc:
        raise _definition_error(str(exc)) from exc


def _definition_mapping(
    value: object, *, field_name: str, maximum_entries: int = 64
) -> dict[str, JsonValue]:
    try:
        return canonical_mapping(
            value,
            field_name=field_name,
            maximum_entries=maximum_entries,
        )
    except (TypeError, ValueError) as exc:
        raise _definition_error(str(exc)) from exc


@dataclass(frozen=True, slots=True)
class RetentionPolicyInput:
    """Logical retention intent consumed by deployment IaC and Adapters.

    This value does not configure an Engine, lock storage, or implement WORM.
    """

    label: str
    classification: str | None = None
    minimum_days: int | None = None
    maximum_days: int | None = None
    disposition: str = "expire"
    extensions: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "label", _definition_string(self.label, "retention label", 256))
        if self.classification is not None:
            object.__setattr__(
                self,
                "classification",
                _definition_string(self.classification, "retention classification", 256),
            )
        for name in ("minimum_days", "maximum_days"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ):
                raise _definition_error(f"{name} must be a non-negative integer")
        if (
            self.minimum_days is not None
            and self.maximum_days is not None
            and self.minimum_days > self.maximum_days
        ):
            raise _definition_error("minimum_days cannot exceed maximum_days")
        if not isinstance(self.disposition, str) or self.disposition not in {
            "expire",
            "archive",
            "review",
        }:
            raise _definition_error("disposition must be expire, archive, or review")
        object.__setattr__(
            self,
            "extensions",
            _definition_mapping(self.extensions, field_name="retention extensions"),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {
            "label": self.label,
            "disposition": self.disposition,
            "extensions": cast(dict[str, JsonValue], dict(self.extensions)),
        }
        optional: dict[str, JsonValue | None] = {
            "classification": self.classification,
            "minimumDays": self.minimum_days,
            "maximumDays": self.maximum_days,
        }
        result.update({key: value for key, value in optional.items() if value is not None})
        return result


@dataclass(frozen=True, slots=True, order=True)
class RedactionRule:
    path: str
    strategy: RedactionStrategy
    replacement: str = "[REDACTED]"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.path, str)
            or len(self.path.encode("utf-8")) > 512
            or _PATH_RE.fullmatch(self.path) is None
        ):
            raise _definition_error("redaction path must contain bounded dotted field names")
        if not isinstance(self.strategy, RedactionStrategy):
            try:
                object.__setattr__(self, "strategy", RedactionStrategy(self.strategy))
            except (TypeError, ValueError) as exc:
                raise _definition_error("invalid redaction strategy") from exc
        object.__setattr__(
            self,
            "replacement",
            _definition_string(self.replacement, "redaction replacement", 256),
        )
        if self.strategy is not RedactionStrategy.REDACT and self.replacement != "[REDACTED]":
            raise _definition_error("replacement is meaningful only for redact rules")

    def to_dict(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {"path": self.path, "strategy": self.strategy.value}
        if self.strategy is RedactionStrategy.REDACT:
            result["replacement"] = self.replacement
        return result


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    data: Mapping[str, JsonValue]
    redacted_paths: tuple[str, ...] = ()
    dropped_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "data",
            _definition_mapping(self.data, field_name="policy data", maximum_entries=256),
        )
        object.__setattr__(self, "redacted_paths", tuple(sorted(set(self.redacted_paths))))
        object.__setattr__(self, "dropped_paths", tuple(sorted(set(self.dropped_paths))))

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "data": cast(dict[str, JsonValue], dict(self.data)),
            "redactedPaths": list(self.redacted_paths),
            "droppedPaths": list(self.dropped_paths),
        }


class CardinalityBudget:
    """Bounded, thread-safe distinct-value tracker that stores only fingerprints."""

    def __init__(self, maximum: int, *, policy_label: str) -> None:
        if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 1:
            raise _definition_error("cardinality maximum must be a positive integer")
        self._maximum = maximum
        self._policy_label = _definition_string(policy_label, "policy label", 256)
        self._seen: set[str] = set()
        self._lock = Lock()

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._seen)

    @property
    def maximum(self) -> int:
        return self._maximum

    def observe(self, partition: str, attributes: Mapping[str, object]) -> None:
        """Atomically reserve distinct attribute values for one logical partition."""

        try:
            logical_partition = bounded_string(partition, "cardinality partition", 512)
            normalized = canonical_mapping(
                attributes,
                field_name="cardinality attributes",
                maximum_entries=10_000,
            )
        except (TypeError, ValueError) as exc:
            raise EvidencePolicyViolation(
                str(exc),
                requirement="evidence.policy.cardinality",
                policy_label=self._policy_label,
            ) from exc
        candidates = {
            sha256_fingerprint(
                {
                    "partition": logical_partition,
                    "attribute": name,
                    "value": value,
                }
            )
            for name, value in normalized.items()
        }
        with self._lock:
            additions = candidates - self._seen
            if len(self._seen) + len(additions) > self._maximum:
                raise EvidencePolicyViolation(
                    "evidence attributes exceed the configured distinct-value budget",
                    requirement="evidence.policy.cardinality",
                    policy_label=self._policy_label,
                    code=EvidenceErrorCode.CARDINALITY_LIMIT,
                )
            self._seen.update(additions)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {"observed": len(self._seen), "maximum": self._maximum}


@dataclass(frozen=True, slots=True)
class EvidencePolicy:
    label: str
    required_fields: Sequence[str] = ()
    redaction_rules: Sequence[RedactionRule] = ()
    atomicity: AtomicityPolicy = AtomicityPolicy.BEST_EFFORT
    retention: RetentionPolicyInput | None = None
    access_scopes: Sequence[str] = ()
    maximum_attributes: int = 128
    maximum_attribute_value_bytes: int = 4096
    maximum_record_bytes: int = 262_144
    cardinality_budget: int = 10_000
    queue_failure: QueueFailurePolicy = QueueFailurePolicy.DROP
    extensions: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "label", _definition_string(self.label, "policy label", 256))
        fields = tuple(
            sorted({self._path(item, "required field") for item in self.required_fields})
        )
        object.__setattr__(self, "required_fields", fields)
        if any(not isinstance(item, RedactionRule) for item in self.redaction_rules):
            raise _definition_error("redaction_rules must contain RedactionRule values")
        rules = tuple(sorted(self.redaction_rules))
        if len({item.path for item in rules}) != len(rules):
            raise _definition_error("redaction rule paths must be unique")
        object.__setattr__(self, "redaction_rules", rules)
        for name, enum_type in (
            ("atomicity", AtomicityPolicy),
            ("queue_failure", QueueFailurePolicy),
        ):
            value = getattr(self, name)
            if not isinstance(value, enum_type):
                try:
                    object.__setattr__(self, name, enum_type(value))
                except (TypeError, ValueError) as exc:
                    raise _definition_error(f"invalid {name}") from exc
        if self.retention is not None and not isinstance(self.retention, RetentionPolicyInput):
            raise _definition_error("retention must be a RetentionPolicyInput")
        object.__setattr__(
            self,
            "access_scopes",
            tuple(
                sorted(
                    {_definition_string(item, "access scope", 256) for item in self.access_scopes}
                )
            ),
        )
        for name, minimum, maximum in (
            ("maximum_attributes", 1, 10_000),
            ("maximum_attribute_value_bytes", 1, 1_048_576),
            ("maximum_record_bytes", 1, 16_777_216),
            ("cardinality_budget", 1, 100_000_000),
        ):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise _definition_error(f"{name} must be between {minimum} and {maximum}")
        object.__setattr__(
            self,
            "extensions",
            _definition_mapping(self.extensions, field_name="policy extensions"),
        )

    @staticmethod
    def _path(value: object, field_name: str) -> str:
        if (
            not isinstance(value, str)
            or len(value.encode("utf-8")) > 512
            or _PATH_RE.fullmatch(value) is None
        ):
            raise _definition_error(f"{field_name} must be a dotted field path")
        return value

    @property
    def requires_atomicity(self) -> bool:
        return self.atomicity is AtomicityPolicy.REQUIRED

    def cardinality_tracker(self) -> CardinalityBudget:
        return CardinalityBudget(self.cardinality_budget, policy_label=self.label)

    def require_access_scope(self, access_scope: str) -> None:
        """Validate an authorization token supplied by the owning application API."""

        try:
            requested = bounded_string(access_scope, "access scope", 256)
        except ValueError as exc:
            raise EvidenceScopeViolation(
                str(exc),
                requirement="evidence.policy.access",
                policy_label=self.label,
            ) from exc
        if self.access_scopes and requested not in self.access_scopes:
            raise EvidenceScopeViolation(
                "the requested Evidence access scope is not permitted by policy",
                requirement="evidence.policy.access",
                policy_label=self.label,
            )

    def apply(self, value: Mapping[str, object]) -> PolicyDecision:
        """Validate and deterministically redact one record mapping."""

        try:
            data = canonical_mapping(value, field_name="evidence record", maximum_entries=512)
        except (TypeError, ValueError) as exc:
            raise EvidencePolicyViolation(
                str(exc),
                requirement="evidence.policy.record",
                policy_label=self.label,
            ) from exc
        for path in self.required_fields:
            exists, _ = _lookup(data, path)
            if not exists:
                raise EvidencePolicyViolation(
                    f"required evidence field {path!r} is missing",
                    requirement="evidence.policy.required-field",
                    policy_label=self.label,
                )
        attributes = data.get("attributes", {})
        if isinstance(attributes, Mapping):
            if len(attributes) > self.maximum_attributes:
                raise EvidencePolicyViolation(
                    "evidence attributes exceed the configured cardinality bound",
                    requirement="evidence.policy.cardinality",
                    policy_label=self.label,
                    code=EvidenceErrorCode.CARDINALITY_LIMIT,
                )
            for key, item in attributes.items():
                encoded = canonical_json(item).encode("utf-8")
                if len(encoded) > self.maximum_attribute_value_bytes:
                    raise EvidencePolicyViolation(
                        f"attribute {key!r} exceeds the configured value bound",
                        requirement="evidence.policy.attribute-size",
                        policy_label=self.label,
                    )
        redacted: list[str] = []
        dropped: list[str] = []
        for rule in self.redaction_rules:
            exists, _ = _lookup(data, rule.path)
            if not exists:
                continue
            if rule.strategy is RedactionStrategy.REJECT:
                raise EvidencePolicyViolation(
                    f"evidence field {rule.path!r} is prohibited by policy",
                    requirement="evidence.policy.redaction",
                    policy_label=self.label,
                )
            if rule.strategy is RedactionStrategy.REDACT:
                _replace(data, rule.path, rule.replacement)
                redacted.append(rule.path)
            else:
                _drop(data, rule.path)
                dropped.append(rule.path)
        if len(canonical_json(data).encode("utf-8")) > self.maximum_record_bytes:
            raise EvidencePolicyViolation(
                "evidence record exceeds the configured byte bound",
                requirement="evidence.policy.record-size",
                policy_label=self.label,
            )
        return PolicyDecision(data, tuple(redacted), tuple(dropped))

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "label": self.label,
            "requiredFields": list(self.required_fields),
            "redactionRules": [item.to_dict() for item in self.redaction_rules],
            "atomicity": self.atomicity.value,
            "retention": None if self.retention is None else self.retention.to_dict(),
            "accessScopes": list(self.access_scopes),
            "maximumAttributes": self.maximum_attributes,
            "maximumAttributeValueBytes": self.maximum_attribute_value_bytes,
            "maximumRecordBytes": self.maximum_record_bytes,
            "cardinalityBudget": self.cardinality_budget,
            "queueFailure": self.queue_failure.value,
            "extensions": cast(dict[str, JsonValue], dict(self.extensions)),
        }


def _lookup(data: Mapping[str, JsonValue], path: str) -> tuple[bool, JsonValue | None]:
    current: JsonValue = cast(dict[str, JsonValue], data)
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return False, None
        current = current[segment]
    return True, current


def _parent(data: dict[str, JsonValue], path: str) -> tuple[dict[str, JsonValue] | None, str]:
    segments = path.split(".")
    current = data
    for segment in segments[:-1]:
        child = current.get(segment)
        if not isinstance(child, dict):
            return None, segments[-1]
        current = child
    return current, segments[-1]


def _replace(data: dict[str, JsonValue], path: str, value: str) -> None:
    parent, key = _parent(data, path)
    if parent is not None and key in parent:
        parent[key] = value


def _drop(data: dict[str, JsonValue], path: str) -> None:
    parent, key = _parent(data, path)
    if parent is not None:
        parent.pop(key, None)


__all__ = [
    "AtomicityPolicy",
    "CardinalityBudget",
    "EvidencePolicy",
    "PolicyDecision",
    "QueueFailurePolicy",
    "RedactionRule",
    "RedactionStrategy",
    "RetentionPolicyInput",
]
