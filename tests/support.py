# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime

from meridian_storage import Operation, OperationContext, OperationResult, ResourceRef

FIXED_TIME = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
FINGERPRINT_1 = "sha256:" + "1" * 64
FINGERPRINT_2 = "sha256:" + "2" * 64
FINGERPRINT_3 = "sha256:" + "3" * 64


def structured_operation(*, read_only: bool = False) -> Operation:
    return Operation(
        catalog="structured",
        operation_contract=(
            "meridian.structured.query" if read_only else "meridian.structured.put"
        ),
        operation_version="1.0.0",
        resources=(ResourceRef("structured", "cases", "open"),),
        input={"where": {"status": "open"}} if read_only else {"data": {"status": "open"}},
        read_only=read_only,
        idempotent=read_only,
    )


def operation_context() -> OperationContext:
    return OperationContext(
        principal_ref="principal:user-1",
        request_id="request-1",
        tenant="tenant-a",
        scope={"environment": "test"},
        correlation_id="correlation-1",
        idempotency_key="operation-idempotency-1",
        trace_context={"traceparent": "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},
    )


def operation_result(operation: Operation) -> OperationResult:
    return OperationResult(
        data={"status": "ok"},
        catalog=operation.catalog,
        operation_contract=operation.operation_contract,
        operation_version=operation.operation_version,
        resources=operation.resources,
        request_id="request-1",
        execution_id="execution-1",
        operation_fingerprint=operation.request_fingerprint,
        registry_fingerprint=FINGERPRINT_1,
        capability_fingerprint=FINGERPRINT_2,
        provenance={"adapter": "conformance", "binding": "binding-a"},
    )
