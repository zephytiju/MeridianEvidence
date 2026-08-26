# SPDX-License-Identifier: Apache-2.0
"""Evidence Catalog Expression surface and Core 1.0.0 provider."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType
from typing import Any, cast

from meridian_storage.registry import CapabilityRequirement

from meridian_storage import CatalogManifest, Expression, Operation, OperationContract, ResourceRef

from ._version import __version__
from .canonical import JsonValue, bounded_string, canonical_mapping
from .errors import InvalidEvidenceDefinition, InvalidEvidenceRecord
from .policy import EvidencePolicy
from .records import EvidenceProfile, EvidenceRecord, record_mapping

EVIDENCE_CONTRACT_VERSION = "1.0.0"
EVIDENCE_REGISTRY_REF = ResourceRef("evidence", "meridian", "registry")
PolicyResolver = Callable[[ResourceRef], EvidencePolicy | None]

_OPERATIONS: Mapping[str, tuple[bool, str, tuple[str, ...]]] = MappingProxyType(
    {
        "append": (False, "conditional", ("append-only",)),
        "create_resource": (False, "always", ("resource-lifecycle",)),
        "publish_schema": (False, "always", ("schema-publication",)),
        "query": (True, "always", ("scope-isolation",)),
    }
)


def evidence_manifest() -> CatalogManifest:
    return CatalogManifest(
        catalog_name="evidence",
        package_name="meridian-storage-evidence",
        package_version=__version__,
        catalog_contract_version=EVIDENCE_CONTRACT_VERSION,
        operations=tuple(
            OperationContract(
                method=method,
                operation_contract=f"meridian.evidence.{method}",
                operation_version="1.0.0",
                read_only=read_only,
                idempotency=idempotency,
                guarantees=guarantees,
            )
            for method, (read_only, idempotency, guarantees) in _OPERATIONS.items()
        ),
        extensions={
            "design.hldRevision": 60,
            "design.catalogRevision": 72,
            "dataFormat": "meridian-evidence-data.v1",
            "profiles": [item.value for item in EvidenceProfile],
            "observabilityFacadeOwner": "meridian-storage-plugin-observability",
        },
    )


class EvidenceCatalogSurface:
    """Mapping-first public Expression syntax for the ``evidence`` Catalog."""

    catalog_name = "evidence"

    def publish_schema(
        self,
        *,
        namespace: str,
        name: str,
        version: str,
        definition: Mapping[str, object],
        expected_registry_revision: int | None = None,
        allow_breaking: bool = False,
    ) -> Expression:
        arguments: dict[str, Any] = {
            "namespace": namespace,
            "name": name,
            "version": version,
            "definition": dict(definition),
            "allowBreaking": allow_breaking,
        }
        if expected_registry_revision is not None:
            arguments["expectedRegistryRevision"] = expected_registry_revision
        return self._expression("publish_schema", arguments)

    def create_resource(
        self,
        *,
        namespace: str,
        name: str,
        schema: Mapping[str, object],
        profile: EvidenceProfile | str,
        policy: EvidencePolicy | Mapping[str, object] | None = None,
        options: Mapping[str, object] | None = None,
    ) -> Expression:
        policy_value: Mapping[str, object] = (
            policy.to_dict() if isinstance(policy, EvidencePolicy) else policy or {}
        )
        return self._expression(
            "create_resource",
            {
                "namespace": namespace,
                "name": name,
                "schema": dict(schema),
                "profile": profile.value if isinstance(profile, EvidenceProfile) else profile,
                "policy": dict(policy_value),
                "options": dict(options or {}),
            },
        )

    def append(
        self,
        *,
        resource: str | Mapping[str, object] | ResourceRef,
        data: Mapping[str, object]
        | EvidenceRecord
        | Sequence[Mapping[str, object] | EvidenceRecord],
        profile: EvidenceProfile | str | None = None,
        idempotency_key: str | None = None,
        require_atomic: bool = False,
    ) -> Expression:
        if isinstance(data, (Mapping, EvidenceRecord)):
            normalized_data: JsonValue = record_mapping(data)
        elif isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray)):
            normalized_data = [record_mapping(item) for item in data]
        else:
            raise InvalidEvidenceRecord(
                "append data must be a record or non-empty record array",
                requirement="expression.append.data",
            )
        arguments: dict[str, Any] = {
            "resource": resource.to_dict() if isinstance(resource, ResourceRef) else resource,
            "data": normalized_data,
            "requireAtomic": require_atomic,
        }
        if profile is not None:
            arguments["profile"] = (
                profile.value if isinstance(profile, EvidenceProfile) else profile
            )
        if idempotency_key is not None:
            arguments["idempotencyKey"] = idempotency_key
        return self._expression("append", arguments)

    def query(
        self,
        *,
        resource: str | Mapping[str, object] | ResourceRef,
        where: Mapping[str, object] | None = None,
        select: Sequence[str] = (),
        order_by: Sequence[Mapping[str, object]] = (),
        limit: int = 50,
        cursor: str | None = None,
        profile: EvidenceProfile | str | None = None,
    ) -> Expression:
        arguments: dict[str, Any] = {
            "resource": resource.to_dict() if isinstance(resource, ResourceRef) else resource,
            "where": dict(where or {}),
            "select": list(select),
            "orderBy": [dict(item) for item in order_by],
            "limit": limit,
        }
        if cursor is not None:
            arguments["cursor"] = cursor
        if profile is not None:
            arguments["profile"] = (
                profile.value if isinstance(profile, EvidenceProfile) else profile
            )
        return self._expression("query", arguments)

    def _expression(self, method: str, arguments: Mapping[str, object]) -> Expression:
        try:
            normalized = canonical_mapping(arguments, field_name=f"evidence.{method}")
        except (TypeError, ValueError) as exc:
            raise InvalidEvidenceDefinition(
                f"evidence.{method} contains invalid JSON data",
                requirement="expression.arguments",
            ) from exc
        return Expression(self.catalog_name, method, normalized)


class EvidenceCatalogProvider:
    catalog_name = "evidence"

    def __init__(self, policy_resolver: PolicyResolver | None = None) -> None:
        self._manifest = evidence_manifest()
        self._policy_resolver = policy_resolver

    def manifest(self) -> CatalogManifest:
        return self._manifest

    def create_surface(self) -> EvidenceCatalogSurface:
        return EvidenceCatalogSurface()

    def normalize(self, expression: Expression) -> Operation:
        return _normalize(expression, self._manifest, self._policy_resolver)


def _normalize(
    expression: Expression,
    manifest: CatalogManifest,
    policy_resolver: PolicyResolver | None,
) -> Operation:
    if expression.catalog != "evidence":
        raise InvalidEvidenceDefinition(
            "Expression Catalog does not match the Evidence provider",
            requirement="expression.catalog",
        )
    try:
        contract = manifest.operation_for(expression.method)
    except KeyError as exc:
        raise InvalidEvidenceDefinition(
            f"unsupported evidence Expression method {expression.method!r}",
            requirement="expression.method",
        ) from exc
    input_value: dict[str, Any] = dict(expression.arguments)
    if expression.method == "publish_schema":
        _validate_publish_schema(input_value)
        resources = (EVIDENCE_REGISTRY_REF,)
    elif expression.method == "create_resource":
        _validate_create_resource(input_value)
        resources = (EVIDENCE_REGISTRY_REF,)
    else:
        resource = _parse_resource(input_value.get("resource"))
        resources = (resource,)
        if expression.method == "append":
            _validate_append(input_value)
            if policy_resolver is not None:
                policy = policy_resolver(resource)
                if policy is not None:
                    _apply_policy(input_value, policy)
        else:
            _validate_query(input_value)
    guarantees = set(contract.guarantees)
    if expression.method == "append" and input_value.get("requireAtomic") is True:
        guarantees.add("atomic-evidence")
    requirement = CapabilityRequirement(
        operation_contract=contract.operation_contract,
        operation_version=contract.operation_version,
        guarantees=tuple(sorted(guarantees)),
        minimum_limits=contract.minimum_limits,
    )
    return Operation(
        catalog="evidence",
        operation_contract=contract.operation_contract,
        operation_version=contract.operation_version,
        resources=resources,
        input=cast(Mapping[str, JsonValue], input_value),
        requirements=(requirement,),
        read_only=contract.read_only,
        idempotent=_is_idempotent(expression.method, input_value),
    )


def _parse_resource(value: object) -> ResourceRef:
    try:
        return ResourceRef.parse(value, catalog="evidence")
    except (TypeError, ValueError) as exc:
        raise InvalidEvidenceDefinition(
            "Operation requires a logical evidence Resource reference",
            requirement="operation.resource",
        ) from exc


def _exact_keys(
    value: Mapping[str, object],
    *,
    required: set[str],
    optional: set[str] | None = None,
    operation: str,
) -> None:
    allowed_optional = optional or set()
    if required - set(value) or set(value) - required - allowed_optional:
        raise InvalidEvidenceDefinition(
            f"evidence.{operation} contains unknown or missing arguments",
            requirement="expression.arguments",
        )


def _validate_publish_schema(value: Mapping[str, object]) -> None:
    _exact_keys(
        value,
        required={"namespace", "name", "version", "definition", "allowBreaking"},
        optional={"expectedRegistryRevision"},
        operation="publish_schema",
    )
    _logical_name(value["namespace"], value["name"])
    bounded_string(value["version"], "Schema version", 128)
    if not isinstance(value["definition"], Mapping):
        raise InvalidEvidenceDefinition(
            "publish_schema definition must be an object",
            requirement="schema.definition",
        )
    if not isinstance(value["allowBreaking"], bool):
        raise InvalidEvidenceDefinition(
            "allowBreaking must be boolean", requirement="schema.compatibility"
        )
    revision = value.get("expectedRegistryRevision")
    if revision is not None and (
        isinstance(revision, bool) or not isinstance(revision, int) or revision < 0
    ):
        raise InvalidEvidenceDefinition(
            "expectedRegistryRevision must be a non-negative integer",
            requirement="registry.compare-and-set",
        )


def _validate_create_resource(value: Mapping[str, object]) -> None:
    _exact_keys(
        value,
        required={"namespace", "name", "schema", "profile", "policy", "options"},
        operation="create_resource",
    )
    _logical_name(value["namespace"], value["name"])
    for name in ("schema", "policy", "options"):
        if not isinstance(value[name], Mapping):
            raise InvalidEvidenceDefinition(
                f"create_resource {name} must be an object",
                requirement=f"resource.{name}",
            )
    _profile(value["profile"])


def _logical_name(namespace: object, name: object) -> None:
    if not isinstance(namespace, str) or not isinstance(name, str):
        raise InvalidEvidenceDefinition(
            "namespace and name must be strings", requirement="resource.identity"
        )
    try:
        ResourceRef("evidence", namespace, name)
    except ValueError as exc:
        raise InvalidEvidenceDefinition(
            "invalid logical evidence Resource name", requirement="resource.identity"
        ) from exc


def _profile(value: object) -> EvidenceProfile:
    if not isinstance(value, str):
        raise InvalidEvidenceDefinition(
            "profile must be telemetry, audit, lineage, or provenance",
            requirement="evidence.profile",
        )
    try:
        return EvidenceProfile(value)
    except (TypeError, ValueError) as exc:
        raise InvalidEvidenceDefinition(
            "profile must be telemetry, audit, lineage, or provenance",
            requirement="evidence.profile",
        ) from exc


def _records(value: object) -> list[dict[str, JsonValue]]:
    if isinstance(value, Mapping):
        return [canonical_mapping(value, field_name="append data")]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if not value or len(value) > 10_000:
            raise InvalidEvidenceDefinition(
                "append batch must contain between 1 and 10000 records",
                requirement="evidence.batch",
            )
        if any(not isinstance(item, Mapping) for item in value):
            raise InvalidEvidenceDefinition(
                "append batch entries must be objects", requirement="evidence.batch"
            )
        return [canonical_mapping(item, field_name="append data") for item in value]
    raise InvalidEvidenceDefinition(
        "append data must be an object or object array", requirement="expression.append.data"
    )


def _validate_append(value: dict[str, Any]) -> None:
    _exact_keys(
        value,
        required={"resource", "data", "requireAtomic"},
        optional={"profile", "idempotencyKey"},
        operation="append",
    )
    records = _records(value["data"])
    value["data"] = records[0] if isinstance(value["data"], Mapping) else records
    if not isinstance(value["requireAtomic"], bool):
        raise InvalidEvidenceDefinition(
            "requireAtomic must be boolean", requirement="evidence.atomicity"
        )
    if "profile" in value:
        _profile(value["profile"])
    if "idempotencyKey" in value:
        bounded_string(value["idempotencyKey"], "idempotency key", 256)


def _validate_query(value: Mapping[str, object]) -> None:
    _exact_keys(
        value,
        required={"resource", "where", "select", "orderBy", "limit"},
        optional={"cursor", "profile"},
        operation="query",
    )
    if not isinstance(value["where"], Mapping):
        raise InvalidEvidenceDefinition("query where must be an object", requirement="query.where")
    for name in ("select", "orderBy"):
        item = value[name]
        if not isinstance(item, Sequence) or isinstance(item, (str, bytes, bytearray)):
            raise InvalidEvidenceDefinition(
                f"query {name} must be an array", requirement="query.structure"
            )
    if any(not isinstance(item, str) for item in cast(Sequence[object], value["select"])):
        raise InvalidEvidenceDefinition(
            "query select must contain field names", requirement="query.structure"
        )
    if any(not isinstance(item, Mapping) for item in cast(Sequence[object], value["orderBy"])):
        raise InvalidEvidenceDefinition(
            "query orderBy must contain objects", requirement="query.structure"
        )
    limit = value["limit"]
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10_000:
        raise InvalidEvidenceDefinition(
            "query limit must be between 1 and 10000", requirement="query.limit"
        )
    if "cursor" in value:
        bounded_string(value["cursor"], "query cursor", 4096)
    if "profile" in value:
        _profile(value["profile"])


def _apply_policy(value: dict[str, Any], policy: EvidencePolicy) -> None:
    records = _records(value["data"])
    decisions = [policy.apply(item) for item in records]
    value["data"] = (
        dict(decisions[0].data)
        if isinstance(value["data"], Mapping)
        else [dict(item.data) for item in decisions]
    )
    value["policy"] = {
        "label": policy.label,
        "redactedPaths": sorted({path for item in decisions for path in item.redacted_paths}),
        "droppedPaths": sorted({path for item in decisions for path in item.dropped_paths}),
    }
    if policy.requires_atomicity:
        value["requireAtomic"] = True


def _is_idempotent(method: str, value: Mapping[str, object]) -> bool:
    if method != "append":
        return True
    if value.get("idempotencyKey") is not None:
        return True
    records = _records(value["data"])
    return all(
        item.get("evidenceId") is not None or item.get("checkpointKey") is not None
        for item in records
    )


__all__ = [
    "EVIDENCE_CONTRACT_VERSION",
    "EVIDENCE_REGISTRY_REF",
    "EvidenceCatalogProvider",
    "EvidenceCatalogSurface",
    "PolicyResolver",
    "evidence_manifest",
]
