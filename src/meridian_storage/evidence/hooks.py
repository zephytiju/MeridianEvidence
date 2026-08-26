# SPDX-License-Identifier: Apache-2.0
"""Explicit audit and lineage hooks for Core Operations.

Hooks return ordinary Evidence Expressions.  Composition code decides when to
execute them and, for required audit, places the mutation and evidence append
in one validated transaction plan.  This module never inspects a Binding or an
Engine configuration.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from meridian_storage import (
    Expression,
    MeridianError,
    Operation,
    OperationContext,
    OperationResult,
    ResourceRef,
)

from .canonical import bounded_string, sha256_fingerprint
from .catalogs import EvidenceCatalogSurface
from .errors import (
    EvidenceCapabilityMismatch,
    InvalidAuditCorrection,
    InvalidEvidenceDefinition,
    InvalidEvidenceRecord,
)
from .records import (
    AuditOutcome,
    AuditRecord,
    Correlation,
    EvidenceMetadata,
    EvidenceReference,
    LineageRecord,
    LineageStatus,
)

Clock = Callable[[], datetime]
_TRACEPARENT_RE = re.compile(
    r"^[0-9a-f]{2}-(?P<trace>[0-9a-f]{32})-(?P<span>[0-9a-f]{16})-[0-9a-f]{2}$"
)


class HookFailureAction(StrEnum):
    """Required caller behavior if an Evidence append cannot complete."""

    CONTINUE = "continue"
    ABORT_TRANSACTION = "abort-transaction"
    RETRY_INCOMPLETE = "retry-incomplete"


@dataclass(frozen=True, slots=True)
class EvidenceHookPlan:
    """Provider-neutral plan returned by an operation evidence hook."""

    expressions: tuple[Expression, ...]
    participating_resources: tuple[ResourceRef, ...]
    atomic: bool = False
    failure_action: HookFailureAction = HookFailureAction.CONTINUE

    def __post_init__(self) -> None:
        if any(item.catalog != "evidence" for item in self.expressions):
            raise InvalidEvidenceDefinition(
                "an Evidence hook plan may contain only Evidence Expressions",
                requirement="evidence.hook.catalog",
            )
        resources = tuple(sorted(set(self.participating_resources)))
        object.__setattr__(self, "participating_resources", resources)
        if self.atomic and self.failure_action is not HookFailureAction.ABORT_TRANSACTION:
            raise InvalidEvidenceDefinition(
                "atomic Evidence requires abort-transaction failure behavior",
                requirement="evidence.atomicity",
            )

    def validate_atomic_resolution(
        self,
        *,
        binding_ids: Mapping[ResourceRef | str, str],
        has_required_transaction_capability: bool,
    ) -> None:
        """Validate caller-supplied logical resolution facts for an atomic plan.

        Binding identifiers are treated as opaque equality tokens.  Credentials,
        endpoints, physical names, or product concepts are neither accepted nor
        exposed.
        """

        if not self.atomic:
            return
        resolved: set[str] = set()
        missing: list[str] = []
        for resource in self.participating_resources:
            value = binding_ids.get(resource)
            if value is None:
                value = binding_ids.get(resource.canonical)
            if value is None:
                missing.append(resource.canonical)
            else:
                try:
                    resolved.add(bounded_string(value, "binding id", 256))
                except ValueError as exc:
                    raise EvidenceCapabilityMismatch(
                        "atomic resolution contains an invalid opaque Binding identifier",
                        requirement="evidence.atomicity.single-binding",
                    ) from exc
        if missing or len(resolved) != 1 or not has_required_transaction_capability:
            raise EvidenceCapabilityMismatch(
                "required atomic evidence must resolve to one transaction-capable Binding",
                requirement="evidence.atomicity.single-binding",
            )


class OperationEvidenceHooks:
    """Build deterministic append plans for query and write Operations."""

    def __init__(
        self,
        *,
        audit_resource: ResourceRef | str = "audit.actions",
        lineage_resource: ResourceRef | str = "lineage.activities",
        clock: Clock | None = None,
    ) -> None:
        self._surface = EvidenceCatalogSurface()
        try:
            self._audit_resource = ResourceRef.parse(audit_resource, catalog="evidence")
            self._lineage_resource = ResourceRef.parse(lineage_resource, catalog="evidence")
        except (TypeError, ValueError) as exc:
            raise InvalidEvidenceDefinition(
                "operation hooks require logical Evidence Resources",
                requirement="evidence.hook.resource",
            ) from exc
        self._clock = clock or (lambda: datetime.now(UTC))

    def started(
        self,
        operation: Operation,
        context: OperationContext,
        *,
        execution_id: str,
        activity: str | None = None,
    ) -> EvidenceHookPlan:
        """Create an idempotent lineage-start append for long-running work."""

        if _is_recursive(operation):
            return _empty_plan()
        timestamp = self._now()
        identity = _event_identity(operation, context, execution_id, "lineage-started")
        record = LineageRecord(
            activity=activity or operation.operation_contract,
            status=LineageStatus.STARTED,
            execution_id=execution_id,
            inputs=_resource_references(operation.resources),
            query_fingerprints=(operation.request_fingerprint,) if operation.read_only else (),
            actor=_principal(context),
            context_scope=context.scope,
            metadata=EvidenceMetadata(
                evidence_id=identity,
                event_time=timestamp,
                observed_time=timestamp,
                tenant=context.tenant,
                scope=context.scope,
                correlation=_correlation(context, operation, execution_id=execution_id),
            ),
        )
        expression = self._surface.append(
            resource=self._lineage_resource,
            data=record,
            idempotency_key=identity,
        )
        return EvidenceHookPlan(
            expressions=(expression,),
            participating_resources=(*operation.resources, self._lineage_resource),
            failure_action=HookFailureAction.RETRY_INCOMPLETE,
        )

    def succeeded(
        self,
        operation: Operation,
        context: OperationContext,
        result: OperationResult,
        *,
        policy_labels: Sequence[str] = (),
        subject: EvidenceReference | None = None,
        required_audit: bool = False,
        atomic: bool = False,
    ) -> EvidenceHookPlan:
        """Create audit and final-lineage appends for a successful Operation."""

        if _is_recursive(operation):
            return _empty_plan()
        _match_result(operation, result)
        if atomic and not required_audit:
            raise InvalidEvidenceDefinition(
                "atomic Evidence is meaningful only for required audit",
                requirement="evidence.atomicity",
            )
        timestamp = self._now()
        audit_identity = _event_identity(operation, context, result.execution_id, "audit-success")
        lineage_identity = _event_identity(
            operation, context, result.execution_id, "lineage-completed"
        )
        common = EvidenceMetadata(
            event_time=timestamp,
            observed_time=timestamp,
            tenant=context.tenant,
            scope=context.scope,
            provenance=result.provenance,
            correlation=_correlation(
                context,
                operation,
                request_id=result.request_id,
                execution_id=result.execution_id,
            ),
        )
        audit = AuditRecord(
            action=operation.operation_contract,
            outcome=AuditOutcome.SUCCESS,
            actor=_principal(context),
            request_id=result.request_id,
            operation=_operation_reference(operation),
            changes={
                "catalog": operation.catalog,
                "resourceCount": len(operation.resources),
                "readOnly": operation.read_only,
                "idempotent": operation.idempotent,
                "executionId": result.execution_id,
            },
            policy_labels=policy_labels,
            binding_provenance=result.provenance,
            metadata=_with_identity(common, audit_identity, subject=subject),
        )
        lineage = LineageRecord(
            activity=operation.operation_contract,
            status=LineageStatus.COMPLETED,
            execution_id=result.execution_id,
            inputs=_resource_references(operation.resources),
            outputs=_resource_references(result.resources),
            query_fingerprints=(operation.request_fingerprint,) if operation.read_only else (),
            source_revisions={"registry": result.registry_fingerprint},
            actor=_principal(context),
            context_scope=context.scope,
            metadata=_with_identity(common, lineage_identity, subject=subject),
        )
        expressions = (
            self._surface.append(
                resource=self._audit_resource,
                data=audit,
                idempotency_key=audit_identity,
                require_atomic=atomic,
            ),
            self._surface.append(
                resource=self._lineage_resource,
                data=lineage,
                idempotency_key=lineage_identity,
            ),
        )
        return EvidenceHookPlan(
            expressions=expressions,
            participating_resources=(
                *operation.resources,
                self._audit_resource,
                self._lineage_resource,
            ),
            atomic=atomic,
            failure_action=(
                HookFailureAction.ABORT_TRANSACTION
                if required_audit
                else HookFailureAction.RETRY_INCOMPLETE
            ),
        )

    def failed(
        self,
        operation: Operation,
        context: OperationContext,
        error: MeridianError,
        *,
        execution_id: str,
        policy_labels: Sequence[str] = (),
        subject: EvidenceReference | None = None,
        required_audit: bool = False,
    ) -> EvidenceHookPlan:
        """Create safe audit and lineage appends without copying error text."""

        if _is_recursive(operation):
            return _empty_plan()
        timestamp = self._now()
        request_id = error.request_id or context.request_id
        resolved_execution_id = error.execution_id or execution_id
        audit_identity = _event_identity(
            operation, context, resolved_execution_id, f"audit-{error.code}"
        )
        lineage_identity = _event_identity(
            operation, context, resolved_execution_id, "lineage-failed"
        )
        provenance = dict(error.adapter_provenance)
        common = EvidenceMetadata(
            event_time=timestamp,
            observed_time=timestamp,
            tenant=context.tenant,
            scope=context.scope,
            provenance=provenance,
            correlation=_correlation(
                context,
                operation,
                request_id=request_id,
                execution_id=resolved_execution_id,
            ),
        )
        outcome = (
            AuditOutcome.DENIED if error.category.value == "authorization" else AuditOutcome.FAILURE
        )
        audit = AuditRecord(
            action=operation.operation_contract,
            outcome=outcome,
            actor=_principal(context),
            request_id=request_id,
            operation=_operation_reference(operation),
            changes={
                "catalog": operation.catalog,
                "resourceCount": len(operation.resources),
                "errorCode": error.code,
                "errorCategory": error.category.value,
                "retryable": error.retryable,
            },
            policy_labels=policy_labels,
            binding_provenance=provenance,
            metadata=_with_identity(common, audit_identity, subject=subject),
        )
        lineage = LineageRecord(
            activity=operation.operation_contract,
            status=LineageStatus.FAILED,
            execution_id=resolved_execution_id,
            inputs=_resource_references(operation.resources),
            query_fingerprints=(operation.request_fingerprint,) if operation.read_only else (),
            actor=_principal(context),
            context_scope=context.scope,
            metadata_values={"errorCode": error.code, "retryable": error.retryable},
            metadata=_with_identity(common, lineage_identity, subject=subject),
        )
        expressions = (
            self._surface.append(
                resource=self._audit_resource,
                data=audit,
                idempotency_key=audit_identity,
            ),
            self._surface.append(
                resource=self._lineage_resource,
                data=lineage,
                idempotency_key=lineage_identity,
            ),
        )
        return EvidenceHookPlan(
            expressions=expressions,
            participating_resources=(
                *operation.resources,
                self._audit_resource,
                self._lineage_resource,
            ),
            failure_action=(
                HookFailureAction.ABORT_TRANSACTION
                if required_audit
                else HookFailureAction.RETRY_INCOMPLETE
            ),
        )

    def checkpoint(
        self,
        operation: Operation,
        context: OperationContext,
        *,
        execution_id: str,
        checkpoint_key: str,
        inputs: Sequence[EvidenceReference] = (),
        outputs: Sequence[EvidenceReference] = (),
        metadata: Mapping[str, object] | None = None,
    ) -> EvidenceHookPlan:
        """Create an idempotent, retryable lineage checkpoint append."""

        if _is_recursive(operation):
            return _empty_plan()
        timestamp = self._now()
        try:
            bounded_checkpoint = bounded_string(checkpoint_key, "checkpoint key", 256)
        except ValueError as exc:
            raise InvalidEvidenceDefinition(
                "lineage checkpoint key must be a bounded token",
                requirement="lineage.checkpoint",
            ) from exc
        identity = _event_identity(
            operation, context, execution_id, f"checkpoint-{bounded_checkpoint}"
        )
        record = LineageRecord(
            activity=operation.operation_contract,
            status=LineageStatus.CHECKPOINT,
            execution_id=execution_id,
            inputs=inputs or _resource_references(operation.resources),
            outputs=outputs,
            query_fingerprints=(operation.request_fingerprint,) if operation.read_only else (),
            actor=_principal(context),
            checkpoint_key=bounded_checkpoint,
            context_scope=context.scope,
            metadata_values=metadata or {},
            metadata=EvidenceMetadata(
                evidence_id=identity,
                event_time=timestamp,
                observed_time=timestamp,
                tenant=context.tenant,
                scope=context.scope,
                correlation=_correlation(context, operation, execution_id=execution_id),
            ),
        )
        expression = self._surface.append(
            resource=self._lineage_resource,
            data=record,
            idempotency_key=identity,
        )
        return EvidenceHookPlan(
            expressions=(expression,),
            participating_resources=(*operation.resources, self._lineage_resource),
            failure_action=HookFailureAction.RETRY_INCOMPLETE,
        )

    def correction(
        self,
        context: OperationContext,
        *,
        prior_audit_id: str,
        action: str,
        outcome: AuditOutcome,
        changes: Mapping[str, object],
        subject: EvidenceReference | None = None,
        policy_labels: Sequence[str] = (),
    ) -> EvidenceHookPlan:
        """Append a correction that retains immutable linkage to prior audit Data."""

        timestamp = self._now()
        try:
            prior = EvidenceReference(kind="audit", value=prior_audit_id)
            normalized_outcome = AuditOutcome(outcome)
        except (TypeError, ValueError, InvalidEvidenceRecord) as exc:
            raise InvalidAuditCorrection(
                "audit correction requires a prior identity and valid outcome"
            ) from exc
        identity = sha256_fingerprint(
            {
                "kind": "audit-correction",
                "prior": prior.to_dict(),
                "action": action,
                "outcome": normalized_outcome.value,
                "requestId": context.request_id,
            }
        )
        record = AuditRecord(
            action=action,
            outcome=normalized_outcome,
            actor=_principal(context),
            request_id=context.request_id,
            changes=changes,
            policy_labels=policy_labels,
            correction_of=prior,
            metadata=EvidenceMetadata(
                evidence_id=identity,
                event_time=timestamp,
                observed_time=timestamp,
                tenant=context.tenant,
                scope=context.scope,
                subject=subject,
                correlation=_context_correlation(context),
            ),
        )
        expression = self._surface.append(
            resource=self._audit_resource,
            data=record,
            idempotency_key=identity,
        )
        return EvidenceHookPlan(
            expressions=(expression,),
            participating_resources=(self._audit_resource,),
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise InvalidEvidenceDefinition(
                "Evidence hook clock must return a timezone-aware timestamp",
                requirement="evidence.hook.clock",
            )
        return value.astimezone(UTC)


def _empty_plan() -> EvidenceHookPlan:
    return EvidenceHookPlan(expressions=(), participating_resources=())


def _is_recursive(operation: Operation) -> bool:
    return bool(operation.catalog == "evidence")


def _principal(context: OperationContext) -> EvidenceReference:
    return EvidenceReference(kind="principal", value=context.principal_ref)


def _resource_references(resources: Collection[ResourceRef]) -> tuple[EvidenceReference, ...]:
    return tuple(
        EvidenceReference(kind="resource", value=resource.canonical)
        for resource in sorted(resources)
    )


def _operation_reference(operation: Operation) -> EvidenceReference:
    return EvidenceReference(
        kind="operation",
        value=operation.operation_contract,
        version=operation.operation_version,
        digest=operation.request_fingerprint,
    )


def _event_identity(
    operation: Operation,
    context: OperationContext,
    execution_id: str,
    phase: str,
) -> str:
    try:
        bounded_execution_id = bounded_string(execution_id, "execution id", 256)
        bounded_phase = bounded_string(phase, "hook phase", 512)
    except ValueError as exc:
        raise InvalidEvidenceDefinition(
            "Evidence hook identity inputs must be bounded tokens",
            requirement="evidence.hook.identity",
        ) from exc
    return sha256_fingerprint(
        {
            "operation": operation.request_fingerprint,
            "requestId": context.request_id,
            "executionId": bounded_execution_id,
            "phase": bounded_phase,
            "tenant": context.tenant,
            "scope": dict(context.scope),
        }
    )


def _trace_ids(context: OperationContext) -> tuple[str | None, str | None]:
    trace_id = context.trace_context.get("traceId") or context.trace_context.get("trace_id")
    span_id = context.trace_context.get("spanId") or context.trace_context.get("span_id")
    traceparent = context.trace_context.get("traceparent")
    if traceparent is not None:
        match = _TRACEPARENT_RE.fullmatch(traceparent.lower())
        if match is not None:
            trace_id = trace_id or match.group("trace")
            span_id = span_id or match.group("span")
    return trace_id, span_id


def _context_correlation(context: OperationContext) -> Correlation:
    trace_id, span_id = _trace_ids(context)
    return Correlation(
        trace_id=trace_id,
        span_id=span_id,
        request_id=context.request_id,
        correlation_id=context.correlation_id,
    )


def _correlation(
    context: OperationContext,
    operation: Operation,
    *,
    request_id: str | None = None,
    execution_id: str | None = None,
) -> Correlation:
    trace_id, span_id = _trace_ids(context)
    return Correlation(
        trace_id=trace_id,
        span_id=span_id,
        request_id=request_id or context.request_id,
        execution_id=execution_id,
        operation_fingerprint=operation.request_fingerprint,
        correlation_id=context.correlation_id,
    )


def _with_identity(
    metadata: EvidenceMetadata,
    identity: str,
    *,
    subject: EvidenceReference | None,
) -> EvidenceMetadata:
    return EvidenceMetadata(
        evidence_id=identity,
        event_time=metadata.event_time,
        observed_time=metadata.observed_time,
        tenant=metadata.tenant,
        scope=metadata.scope,
        otel_resource=metadata.otel_resource,
        instrumentation_scope=metadata.instrumentation_scope,
        ingestion_identity=metadata.ingestion_identity,
        source_protocol_version=metadata.source_protocol_version,
        attributes=metadata.attributes,
        provenance=metadata.provenance,
        subject=subject,
        correlation=metadata.correlation,
        extensions=metadata.extensions,
    )


def _match_result(operation: Operation, result: OperationResult) -> None:
    if (
        result.catalog != operation.catalog
        or result.operation_contract != operation.operation_contract
        or result.operation_version != operation.operation_version
        or result.operation_fingerprint != operation.request_fingerprint
    ):
        raise InvalidEvidenceDefinition(
            "OperationResult does not match the hooked Operation",
            requirement="evidence.hook.result",
        )


__all__ = [
    "Clock",
    "EvidenceHookPlan",
    "HookFailureAction",
    "OperationEvidenceHooks",
]
