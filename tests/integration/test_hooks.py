# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime

import pytest

from meridian_storage import (
    ErrorCode,
    OperationResult,
    ResourceRef,
    ValidationError,
)
from meridian_storage.evidence import (
    AuditOutcome,
    EvidenceCapabilityMismatch,
    EvidenceCatalogProvider,
    EvidenceReference,
    HookFailureAction,
    InvalidAuditCorrection,
    InvalidEvidenceDefinition,
    OperationEvidenceHooks,
)
from tests.support import FIXED_TIME, operation_context, operation_result, structured_operation


def _append_data(plan_index: int, plan: object) -> object:
    expression = plan.expressions[plan_index]  # type: ignore[attr-defined]
    return expression.arguments["data"]


def test_success_hook_propagates_context_provenance_and_trace() -> None:
    operation = structured_operation(read_only=True)
    context = operation_context()
    result = operation_result(operation)
    hooks = OperationEvidenceHooks(clock=lambda: FIXED_TIME)
    plan = hooks.succeeded(
        operation,
        context,
        result,
        policy_labels=("audit-required",),
        subject=EvidenceReference("resource", "structured:cases.open"),
        required_audit=True,
        atomic=True,
    )
    assert plan.atomic is True
    assert plan.failure_action is HookFailureAction.ABORT_TRANSACTION
    assert tuple(item.method for item in plan.expressions) == ("append", "append")
    audit = _append_data(0, plan)
    lineage = _append_data(1, plan)
    assert audit["outcome"] == "success"  # type: ignore[index]
    assert audit["correlation"]["traceId"] == "0123456789abcdef0123456789abcdef"  # type: ignore[index]
    assert audit["bindingProvenance"]["adapter"] == "conformance"  # type: ignore[index]
    assert "request" not in audit["changes"]  # type: ignore[operator]
    assert lineage["status"] == "completed"  # type: ignore[index]
    assert lineage["queryFingerprints"] == (operation.request_fingerprint,)  # type: ignore[index]
    normalized = EvidenceCatalogProvider().normalize(plan.expressions[0])
    assert "atomic-evidence" in normalized.requirements[0].guarantees


def test_atomic_resolution_requires_one_capable_binding() -> None:
    operation = structured_operation()
    plan = OperationEvidenceHooks(clock=lambda: FIXED_TIME).succeeded(
        operation,
        operation_context(),
        operation_result(operation),
        required_audit=True,
        atomic=True,
    )
    bindings = {item: "binding-a" for item in plan.participating_resources}
    plan.validate_atomic_resolution(
        binding_ids=bindings,
        has_required_transaction_capability=True,
    )
    broken = dict(bindings)
    broken[plan.participating_resources[-1]] = "binding-b"
    with pytest.raises(EvidenceCapabilityMismatch):
        plan.validate_atomic_resolution(
            binding_ids=broken,
            has_required_transaction_capability=True,
        )
    with pytest.raises(EvidenceCapabilityMismatch):
        plan.validate_atomic_resolution(
            binding_ids={},
            has_required_transaction_capability=False,
        )


def test_started_checkpoint_and_failure_are_idempotent_and_retryable() -> None:
    operation = structured_operation()
    context = operation_context()
    hooks = OperationEvidenceHooks(clock=lambda: FIXED_TIME)
    started = hooks.started(operation, context, execution_id="execution-1")
    checkpoint = hooks.checkpoint(
        operation,
        context,
        execution_id="execution-1",
        checkpoint_key="page-2",
        metadata={"cursor": "opaque"},
    )
    error = ValidationError(
        ErrorCode.OPERATION_INVALID,
        "safe message must not be copied",
        request_id="request-1",
        execution_id="execution-1",
        adapter_provenance={"adapter": "conformance"},
    )
    failed = hooks.failed(operation, context, error, execution_id="execution-1")
    assert _append_data(0, started)["status"] == "started"  # type: ignore[index]
    assert _append_data(0, checkpoint)["checkpointKey"] == "page-2"  # type: ignore[index]
    assert checkpoint.failure_action is HookFailureAction.RETRY_INCOMPLETE
    audit = _append_data(0, failed)
    lineage = _append_data(1, failed)
    assert audit["outcome"] == "failure"  # type: ignore[index]
    assert audit["changes"]["errorCode"] == str(ErrorCode.OPERATION_INVALID)  # type: ignore[index]
    assert "safe message" not in str(audit)
    assert lineage["status"] == "failed"  # type: ignore[index]
    assert EvidenceCatalogProvider().normalize(checkpoint.expressions[0]).idempotent is True


def test_audit_correction_links_prior_identity() -> None:
    hooks = OperationEvidenceHooks(clock=lambda: FIXED_TIME)
    first = hooks.correction(
        operation_context(),
        prior_audit_id="audit-1",
        action="case.updated.corrected",
        outcome=AuditOutcome.SUCCESS,
        changes={"fieldCount": 1},
    )
    second = hooks.correction(
        operation_context(),
        prior_audit_id="audit-1",
        action="case.updated.corrected",
        outcome=AuditOutcome.SUCCESS,
        changes={"fieldCount": 1},
    )
    assert first.expressions[0].fingerprint == second.expressions[0].fingerprint
    assert _append_data(0, first)["correctionOf"] == {  # type: ignore[index]
        "kind": "audit",
        "value": "audit-1",
    }
    with pytest.raises(InvalidAuditCorrection):
        hooks.correction(
            operation_context(),
            prior_audit_id="",
            action="bad",
            outcome=AuditOutcome.SUCCESS,
            changes={},
        )


def test_hooks_suppress_recursive_evidence_and_validate_inputs() -> None:
    evidence_operation = EvidenceCatalogProvider().normalize(
        EvidenceCatalogProvider().create_surface().query(resource="runtime.logs")
    )
    hooks = OperationEvidenceHooks(clock=lambda: FIXED_TIME)
    empty = hooks.started(evidence_operation, operation_context(), execution_id="execution-1")
    assert empty.expressions == ()
    empty.validate_atomic_resolution(
        binding_ids={},
        has_required_transaction_capability=False,
    )
    operation = structured_operation()
    result = operation_result(operation)
    mismatched = OperationResult(
        data={},
        catalog=result.catalog,
        operation_contract=result.operation_contract,
        operation_version=result.operation_version,
        resources=result.resources,
        request_id=result.request_id,
        execution_id=result.execution_id,
        operation_fingerprint="sha256:" + "f" * 64,
        registry_fingerprint=result.registry_fingerprint,
        capability_fingerprint=result.capability_fingerprint,
    )
    with pytest.raises(InvalidEvidenceDefinition, match="does not match"):
        hooks.succeeded(operation, operation_context(), mismatched)
    with pytest.raises(InvalidEvidenceDefinition, match="meaningful"):
        hooks.succeeded(operation, operation_context(), result, atomic=True)
    naive = OperationEvidenceHooks(clock=lambda: datetime(2026, 8, 25))
    with pytest.raises(InvalidEvidenceDefinition, match="timezone-aware"):
        naive.started(operation, operation_context(), execution_id="execution-1")


def test_hook_plan_rejects_invalid_atomic_failure_action() -> None:
    from meridian_storage.evidence import EvidenceHookPlan

    with pytest.raises(InvalidEvidenceDefinition, match="abort-transaction"):
        EvidenceHookPlan(
            expressions=(),
            participating_resources=(ResourceRef("structured", "a", "b"),),
            atomic=True,
        )
