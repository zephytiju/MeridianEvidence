# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from meridian_storage import CompatibilityError, ConstraintError, ValidationError
from meridian_storage.evidence import (
    EVIDENCE_ERROR_CODES,
    EvidenceCapabilityMismatch,
    EvidenceErrorCode,
    EvidenceIdempotencyConflict,
    EvidencePolicyViolation,
    EvidenceQueueExhausted,
    InvalidAuditCorrection,
    InvalidEvidenceDefinition,
    InvalidEvidenceRecord,
    LineageCheckpointIncomplete,
)


def test_error_envelope_is_stable_and_sorted() -> None:
    error = InvalidEvidenceDefinition(
        "invalid",
        requirement="record.field",
        logical_references=("evidence:z.logs", "evidence:a.logs", "evidence:z.logs"),
        policy_label="policy-a",
        request_id="request-1",
    )
    assert isinstance(error, ValidationError)
    assert error.to_dict() == {
        "code": "MERIDIAN_EVIDENCE_INVALID_DEFINITION",
        "category": "VALIDATION",
        "message": "invalid",
        "retryable": False,
        "requestId": "request-1",
        "requirement": "record.field",
        "logicalReferences": ["evidence:a.logs", "evidence:z.logs"],
        "policyLabel": "policy-a",
    }


def test_error_categories_and_retryability() -> None:
    assert isinstance(InvalidEvidenceRecord("bad"), ValidationError)
    assert isinstance(EvidencePolicyViolation("bad"), ConstraintError)
    assert isinstance(EvidenceCapabilityMismatch("bad"), CompatibilityError)
    assert EvidenceQueueExhausted().retryable is True
    assert LineageCheckpointIncomplete().retryable is True
    assert EvidenceIdempotencyConflict("conflict").category.value == "CONFLICT"
    correction = InvalidAuditCorrection("bad correction")
    assert correction.code == EvidenceErrorCode.CORRECTION_INVALID
    assert correction.to_dict()["requirement"] == "evidence.audit.correction"


def test_error_code_ledger_is_exhaustive() -> None:
    assert tuple(item.value for item in EvidenceErrorCode) == EVIDENCE_ERROR_CODES
    assert len(EVIDENCE_ERROR_CODES) == len(set(EVIDENCE_ERROR_CODES))


def test_error_detail_bounds() -> None:
    with pytest.raises(ValueError, match="bounded"):
        InvalidEvidenceDefinition("bad", requirement="x" * 300)
