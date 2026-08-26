# SPDX-License-Identifier: Apache-2.0
"""Stable, provider-neutral Evidence failures."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, cast

from meridian_storage import (
    AuthorizationError,
    CompatibilityError,
    ConflictError,
    ConstraintError,
    TransientError,
    UnavailableError,
    ValidationError,
)

from .canonical import bounded_string


class EvidenceErrorCode(StrEnum):
    INVALID_DEFINITION = "MERIDIAN_EVIDENCE_INVALID_DEFINITION"
    INVALID_RECORD = "MERIDIAN_EVIDENCE_INVALID_RECORD"
    POLICY_VIOLATION = "MERIDIAN_EVIDENCE_POLICY_VIOLATION"
    CARDINALITY_LIMIT = "MERIDIAN_EVIDENCE_CARDINALITY_LIMIT"
    SCOPE_VIOLATION = "MERIDIAN_EVIDENCE_SCOPE_VIOLATION"
    CAPABILITY_MISMATCH = "MERIDIAN_EVIDENCE_CAPABILITY_MISMATCH"
    IDEMPOTENCY_CONFLICT = "MERIDIAN_EVIDENCE_IDEMPOTENCY_CONFLICT"
    CORRECTION_INVALID = "MERIDIAN_EVIDENCE_CORRECTION_INVALID"
    QUEUE_EXHAUSTED = "MERIDIAN_EVIDENCE_QUEUE_EXHAUSTED"
    CHECKPOINT_INCOMPLETE = "MERIDIAN_EVIDENCE_CHECKPOINT_INCOMPLETE"


class _EvidenceErrorMixin:
    requirement: str | None
    logical_references: tuple[str, ...]
    policy_label: str | None

    def _set_evidence_details(
        self,
        *,
        requirement: str | None,
        logical_references: tuple[str, ...],
        policy_label: str | None,
    ) -> None:
        self.requirement = (
            None if requirement is None else bounded_string(requirement, "requirement", 256)
        )
        self.logical_references = tuple(
            sorted({bounded_string(item, "logical reference", 512) for item in logical_references})
        )
        self.policy_label = (
            None if policy_label is None else bounded_string(policy_label, "policy label", 256)
        )

    def to_dict(self) -> dict[str, Any]:
        payload = cast(dict[str, Any], super().to_dict())  # type: ignore[misc]
        if self.requirement is not None:
            payload["requirement"] = self.requirement
        if self.logical_references:
            payload["logicalReferences"] = list(self.logical_references)
        if self.policy_label is not None:
            payload["policyLabel"] = self.policy_label
        return payload


class InvalidEvidenceDefinition(_EvidenceErrorMixin, ValidationError):
    def __init__(
        self,
        message: str,
        *,
        requirement: str | None = None,
        logical_references: tuple[str, ...] = (),
        policy_label: str | None = None,
        code: EvidenceErrorCode = EvidenceErrorCode.INVALID_DEFINITION,
        **details: Any,
    ) -> None:
        self._set_evidence_details(
            requirement=requirement,
            logical_references=logical_references,
            policy_label=policy_label,
        )
        super().__init__(code, message, **details)


class InvalidEvidenceRecord(InvalidEvidenceDefinition):
    def __init__(
        self,
        message: str,
        *,
        code: EvidenceErrorCode = EvidenceErrorCode.INVALID_RECORD,
        **details: Any,
    ) -> None:
        super().__init__(message, code=code, **details)


class InvalidAuditCorrection(InvalidEvidenceRecord):
    def __init__(self, message: str, **details: Any) -> None:
        details.setdefault("requirement", "evidence.audit.correction")
        super().__init__(message, code=EvidenceErrorCode.CORRECTION_INVALID, **details)


class EvidencePolicyViolation(_EvidenceErrorMixin, ConstraintError):
    def __init__(
        self,
        message: str,
        *,
        requirement: str | None = None,
        logical_references: tuple[str, ...] = (),
        policy_label: str | None = None,
        code: EvidenceErrorCode = EvidenceErrorCode.POLICY_VIOLATION,
        **details: Any,
    ) -> None:
        self._set_evidence_details(
            requirement=requirement,
            logical_references=logical_references,
            policy_label=policy_label,
        )
        super().__init__(code, message, **details)


class EvidenceScopeViolation(_EvidenceErrorMixin, AuthorizationError):
    def __init__(
        self,
        message: str,
        *,
        requirement: str = "evidence.scope",
        logical_references: tuple[str, ...] = (),
        policy_label: str | None = None,
        **details: Any,
    ) -> None:
        self._set_evidence_details(
            requirement=requirement,
            logical_references=logical_references,
            policy_label=policy_label,
        )
        super().__init__(EvidenceErrorCode.SCOPE_VIOLATION, message, **details)


class EvidenceCapabilityMismatch(_EvidenceErrorMixin, CompatibilityError):
    def __init__(
        self, message: str, *, requirement: str = "evidence.capability", **details: Any
    ) -> None:
        self._set_evidence_details(
            requirement=requirement, logical_references=(), policy_label=None
        )
        super().__init__(EvidenceErrorCode.CAPABILITY_MISMATCH, message, **details)


class EvidenceIdempotencyConflict(_EvidenceErrorMixin, ConflictError):
    def __init__(self, message: str, **details: Any) -> None:
        self._set_evidence_details(
            requirement="evidence.idempotency", logical_references=(), policy_label=None
        )
        super().__init__(EvidenceErrorCode.IDEMPOTENCY_CONFLICT, message, **details)


class EvidenceQueueExhausted(_EvidenceErrorMixin, UnavailableError):
    def __init__(
        self, message: str = "bounded evidence queue is exhausted", **details: Any
    ) -> None:
        self._set_evidence_details(
            requirement="evidence.queue", logical_references=(), policy_label=None
        )
        details.setdefault("retryable", True)
        super().__init__(EvidenceErrorCode.QUEUE_EXHAUSTED, message, **details)


class LineageCheckpointIncomplete(_EvidenceErrorMixin, TransientError):
    def __init__(
        self, message: str = "lineage checkpoint remains incomplete", **details: Any
    ) -> None:
        self._set_evidence_details(
            requirement="lineage.checkpoint", logical_references=(), policy_label=None
        )
        super().__init__(EvidenceErrorCode.CHECKPOINT_INCOMPLETE, message, **details)


EVIDENCE_ERROR_CODES = tuple(item.value for item in EvidenceErrorCode)

__all__ = [
    "EVIDENCE_ERROR_CODES",
    "EvidenceCapabilityMismatch",
    "EvidenceErrorCode",
    "EvidenceIdempotencyConflict",
    "EvidencePolicyViolation",
    "EvidenceQueueExhausted",
    "EvidenceScopeViolation",
    "InvalidAuditCorrection",
    "InvalidEvidenceDefinition",
    "InvalidEvidenceRecord",
    "LineageCheckpointIncomplete",
]
