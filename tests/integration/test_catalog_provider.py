# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Mapping

import pytest

from meridian_storage import Expression, ResourceRef
from meridian_storage.evidence import (
    AtomicityPolicy,
    EvidenceCatalogProvider,
    EvidencePolicy,
    EvidenceProfile,
    InvalidEvidenceDefinition,
    LogRecord,
    RedactionRule,
    RedactionStrategy,
    evidence_manifest,
)


def test_manifest_matches_core_exhaustive_registry() -> None:
    manifest = evidence_manifest()
    assert manifest.catalog_name == "evidence"
    assert manifest.package_name == "meridian-storage-evidence"
    assert tuple(item.method for item in manifest.operations) == (
        "append",
        "create_resource",
        "publish_schema",
        "query",
    )
    assert manifest.extensions["design.catalogRevision"] == 72
    assert manifest.extensions["observabilityFacadeOwner"] == (
        "meridian-storage-plugin-observability"
    )


def test_all_mapping_surfaces_normalize_to_engine_neutral_operations() -> None:
    provider = EvidenceCatalogProvider()
    surface = provider.create_surface()
    expressions = (
        surface.publish_schema(
            namespace="runtime",
            name="log",
            version="1.0.0",
            definition={"type": "object"},
            expected_registry_revision=4,
        ),
        surface.create_resource(
            namespace="runtime",
            name="logs",
            schema={"namespace": "runtime", "name": "log", "version": "1.0.0"},
            profile=EvidenceProfile.TELEMETRY,
            options={"partition": "tenant"},
        ),
        surface.append(
            resource="runtime.logs",
            data=LogRecord("INFO", "ready"),
            idempotency_key="log-1",
        ),
        surface.query(
            resource=ResourceRef("evidence", "runtime", "logs"),
            where={"severity": {"eq": "INFO"}},
            select=("eventTime", "body"),
            order_by=({"field": "eventTime", "direction": "desc"},),
            limit=10,
            cursor="cursor-1",
            profile="telemetry",
        ),
    )
    operations = tuple(provider.normalize(item) for item in expressions)
    assert tuple(item.operation_contract for item in operations) == (
        "meridian.evidence.publish_schema",
        "meridian.evidence.create_resource",
        "meridian.evidence.append",
        "meridian.evidence.query",
    )
    assert operations[0].resources == (ResourceRef("evidence", "meridian", "registry"),)
    assert operations[1].resources == (ResourceRef("evidence", "meridian", "registry"),)
    assert operations[2].resources == (ResourceRef("evidence", "runtime", "logs"),)
    assert operations[3].read_only is True
    assert operations[2].idempotent is True
    assert operations[3].idempotent is True
    assert all(item.catalog == "evidence" for item in operations)


def test_append_batch_idempotency_and_atomic_guarantee() -> None:
    provider = EvidenceCatalogProvider()
    surface = provider.create_surface()
    non_idempotent = provider.normalize(
        surface.append(resource="runtime.logs", data=[{"body": "a"}, {"body": "b"}])
    )
    idempotent = provider.normalize(
        surface.append(
            resource="runtime.logs",
            data=[{"evidenceId": "a"}, {"checkpointKey": "b"}],
            require_atomic=True,
        )
    )
    assert non_idempotent.idempotent is False
    assert idempotent.idempotent is True
    assert idempotent.requirements[0].guarantees == ("append-only", "atomic-evidence")


def test_policy_resolver_redacts_and_requires_atomicity() -> None:
    policy = EvidencePolicy(
        "audit-required",
        redaction_rules=(RedactionRule("attributes.secret", RedactionStrategy.REDACT),),
        atomicity=AtomicityPolicy.REQUIRED,
    )
    seen: list[ResourceRef] = []

    def resolve(resource: ResourceRef) -> EvidencePolicy:
        seen.append(resource)
        return policy

    provider = EvidenceCatalogProvider(resolve)
    operation = provider.normalize(
        provider.create_surface().append(
            resource="audit.actions",
            data={"action": "read", "attributes": {"secret": "value"}},
        )
    )
    assert seen == [ResourceRef("evidence", "audit", "actions")]
    assert operation.input["data"]["attributes"]["secret"] == "[REDACTED]"  # type: ignore[index]
    assert operation.input["requireAtomic"] is True
    assert operation.input["policy"]["label"] == "audit-required"  # type: ignore[index]


@pytest.mark.parametrize(
    "expression",
    [
        Expression("structured", "query", {"resource": "runtime.logs"}),
        Expression("evidence", "append", {"resource": "bad", "data": {}, "requireAtomic": False}),
        Expression(
            "evidence", "append", {"resource": "runtime.logs", "data": [], "requireAtomic": False}
        ),
        Expression(
            "evidence", "append", {"resource": "runtime.logs", "data": {}, "requireAtomic": "yes"}
        ),
        Expression(
            "evidence",
            "append",
            {"resource": "runtime.logs", "data": {}, "requireAtomic": False, "profile": "other"},
        ),
        Expression(
            "evidence",
            "query",
            {"resource": "runtime.logs", "where": [], "select": [], "orderBy": [], "limit": 1},
        ),
        Expression(
            "evidence",
            "query",
            {"resource": "runtime.logs", "where": {}, "select": "body", "orderBy": [], "limit": 1},
        ),
        Expression(
            "evidence",
            "query",
            {"resource": "runtime.logs", "where": {}, "select": [], "orderBy": [], "limit": 0},
        ),
    ],
)
def test_invalid_expressions_have_normalized_failures(expression: Expression) -> None:
    with pytest.raises(InvalidEvidenceDefinition):
        EvidenceCatalogProvider().normalize(expression)


def test_unknown_method_and_argument_are_rejected() -> None:
    provider = EvidenceCatalogProvider()
    with pytest.raises(InvalidEvidenceDefinition, match="unsupported"):
        provider.normalize(Expression("evidence", "delete", {}))
    with pytest.raises(InvalidEvidenceDefinition, match="unknown or missing"):
        provider.normalize(
            Expression(
                "evidence",
                "publish_schema",
                {
                    "namespace": "runtime",
                    "name": "log",
                    "version": "1",
                    "definition": {},
                    "allowBreaking": False,
                    "extra": True,
                },
            )
        )


@pytest.mark.parametrize(
    "arguments",
    [
        {"namespace": 1, "name": "log", "version": "1", "definition": {}, "allowBreaking": False},
        {
            "namespace": "runtime",
            "name": "log",
            "version": "1",
            "definition": [],
            "allowBreaking": False,
        },
        {
            "namespace": "runtime",
            "name": "log",
            "version": "1",
            "definition": {},
            "allowBreaking": "no",
        },
        {
            "namespace": "runtime",
            "name": "log",
            "version": "1",
            "definition": {},
            "allowBreaking": False,
            "expectedRegistryRevision": -1,
        },
    ],
)
def test_publish_schema_validation(arguments: Mapping[str, object]) -> None:
    with pytest.raises(InvalidEvidenceDefinition):
        EvidenceCatalogProvider().normalize(Expression("evidence", "publish_schema", arguments))


def test_surface_rejects_non_json_and_invalid_append_data() -> None:
    surface = EvidenceCatalogProvider().create_surface()
    with pytest.raises(InvalidEvidenceDefinition):
        surface.publish_schema(
            namespace="runtime",
            name="bad",
            version="1",
            definition={"bad": object()},
        )
    with pytest.raises(Exception, match="append data"):
        surface.append(resource="runtime.logs", data="bad")  # type: ignore[arg-type]
