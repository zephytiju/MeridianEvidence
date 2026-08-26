# SPDX-License-Identifier: Apache-2.0
"""Engine-neutral Evidence query helpers."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import cast

from meridian_storage import Expression, OperationResult, ResourceRef

from .canonical import JsonValue, bounded_string, canonical_mapping, sha256_fingerprint
from .catalogs import EvidenceCatalogSurface
from .errors import InvalidEvidenceDefinition
from .records import EvidenceProfile

_FIELD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z][A-Za-z0-9_-]*)*$")


class QueryDirection(StrEnum):
    ASCENDING = "asc"
    DESCENDING = "desc"


@dataclass(frozen=True, slots=True, order=True)
class QueryOrder:
    field: str
    direction: QueryDirection = QueryDirection.ASCENDING

    def __post_init__(self) -> None:
        _field_name(self.field)
        if not isinstance(self.direction, QueryDirection):
            try:
                object.__setattr__(self, "direction", QueryDirection(self.direction))
            except ValueError as exc:
                raise InvalidEvidenceDefinition(
                    "query direction must be asc or desc",
                    requirement="query.order",
                ) from exc

    def to_dict(self) -> dict[str, str]:
        return {"field": self.field, "direction": self.direction.value}


@dataclass(frozen=True, slots=True)
class EvidenceQuery:
    """Portable query value that compiles to ``evidence.query`` syntax.

    ``where`` intentionally remains a mapping so the separately released shared
    Query library can supply its versioned node structure without a source-tree
    dependency.
    """

    resource: ResourceRef | str | Mapping[str, object]
    where: Mapping[str, object] = field(default_factory=dict)
    select: Sequence[str] = ()
    order_by: Sequence[QueryOrder | Mapping[str, object]] = ()
    limit: int = 50
    cursor: str | None = None
    profile: EvidenceProfile | None = None

    def __post_init__(self) -> None:
        try:
            resource = ResourceRef.parse(self.resource, catalog="evidence")
        except (TypeError, ValueError) as exc:
            raise InvalidEvidenceDefinition(
                "EvidenceQuery requires a logical Evidence Resource",
                requirement="query.resource",
            ) from exc
        object.__setattr__(self, "resource", resource)
        try:
            normalized_where = canonical_mapping(self.where, field_name="query where")
        except (TypeError, ValueError) as exc:
            raise InvalidEvidenceDefinition(
                "query where must be canonical JSON",
                requirement="query.where",
            ) from exc
        object.__setattr__(self, "where", normalized_where)
        fields = tuple(_field_name(item) for item in self.select)
        if len(set(fields)) != len(fields):
            raise InvalidEvidenceDefinition(
                "query select fields must be unique",
                requirement="query.select",
            )
        object.__setattr__(self, "select", fields)
        orders = tuple(_order(item) for item in self.order_by)
        if len({item.field for item in orders}) != len(orders):
            raise InvalidEvidenceDefinition(
                "query order fields must be unique",
                requirement="query.order",
            )
        object.__setattr__(self, "order_by", orders)
        if (
            isinstance(self.limit, bool)
            or not isinstance(self.limit, int)
            or not 1 <= self.limit <= 10_000
        ):
            raise InvalidEvidenceDefinition(
                "query limit must be between 1 and 10000",
                requirement="query.limit",
            )
        if self.cursor is not None:
            try:
                object.__setattr__(
                    self, "cursor", bounded_string(self.cursor, "query cursor", 4096)
                )
            except ValueError as exc:
                raise InvalidEvidenceDefinition(
                    "query cursor must be an opaque bounded token",
                    requirement="query.cursor",
                ) from exc
        if self.profile is not None and not isinstance(self.profile, EvidenceProfile):
            try:
                object.__setattr__(self, "profile", EvidenceProfile(self.profile))
            except ValueError as exc:
                raise InvalidEvidenceDefinition(
                    "invalid Evidence query profile",
                    requirement="query.profile",
                ) from exc

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())

    def to_dict(self) -> dict[str, JsonValue]:
        resource = cast(ResourceRef, self.resource)
        result: dict[str, JsonValue] = {
            "resource": resource.to_dict(),
            "where": cast(dict[str, JsonValue], dict(self.where)),
            "select": list(self.select),
            "orderBy": [
                cast(JsonValue, cast(QueryOrder, item).to_dict()) for item in self.order_by
            ],
            "limit": self.limit,
        }
        if self.cursor is not None:
            result["cursor"] = self.cursor
        if self.profile is not None:
            result["profile"] = self.profile.value
        return result

    def expression(self, surface: EvidenceCatalogSurface | None = None) -> Expression:
        selected_surface = surface or EvidenceCatalogSurface()
        resource = cast(ResourceRef, self.resource)
        return selected_surface.query(
            resource=resource,
            where=self.where,
            select=self.select,
            order_by=[cast(QueryOrder, item).to_dict() for item in self.order_by],
            limit=self.limit,
            cursor=self.cursor,
            profile=self.profile,
        )


@dataclass(frozen=True, slots=True)
class EvidenceQueryResult:
    """Backend-independent result envelope retaining Core provenance."""

    data: JsonValue
    request_id: str
    execution_id: str
    operation_fingerprint: str
    registry_fingerprint: str
    capability_fingerprint: str
    provenance: Mapping[str, str]

    @classmethod
    def from_operation_result(cls, result: OperationResult) -> EvidenceQueryResult:
        if result.catalog != "evidence" or result.operation_contract != "meridian.evidence.query":
            raise InvalidEvidenceDefinition(
                "query result must originate from meridian.evidence.query",
                requirement="query.result",
            )
        return cls(
            data=cast(JsonValue, result.to_dict()["data"]),
            request_id=result.request_id,
            execution_id=result.execution_id,
            operation_fingerprint=result.operation_fingerprint,
            registry_fingerprint=result.registry_fingerprint,
            capability_fingerprint=result.capability_fingerprint,
            provenance=dict(result.provenance),
        )


def _field_name(value: object) -> str:
    if not isinstance(value, str) or _FIELD_RE.fullmatch(value) is None:
        raise InvalidEvidenceDefinition(
            "query fields must be bounded dotted names",
            requirement="query.field",
        )
    try:
        return bounded_string(value, "query field", 512)
    except ValueError as exc:
        raise InvalidEvidenceDefinition(
            "query fields must be bounded dotted names",
            requirement="query.field",
        ) from exc


def _order(value: QueryOrder | Mapping[str, object]) -> QueryOrder:
    if isinstance(value, QueryOrder):
        return value
    if not isinstance(value, Mapping) or set(value) != {"field", "direction"}:
        raise InvalidEvidenceDefinition(
            "query order requires field and direction",
            requirement="query.order",
        )
    field_name = value["field"]
    direction = value["direction"]
    if not isinstance(field_name, str) or not isinstance(direction, str):
        raise InvalidEvidenceDefinition(
            "query order field and direction must be strings",
            requirement="query.order",
        )
    return QueryOrder(field=field_name, direction=cast(QueryDirection, direction))


__all__ = ["EvidenceQuery", "EvidenceQueryResult", "QueryDirection", "QueryOrder"]
