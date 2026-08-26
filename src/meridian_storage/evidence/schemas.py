# SPDX-License-Identifier: Apache-2.0
"""Packaged Evidence JSON Schemas and Core schema-provider integration."""

from __future__ import annotations

import json
from collections.abc import Mapping
from importlib import resources as package_resources
from pathlib import Path
from typing import cast

from meridian_storage.registry import (
    NamespaceDefinition,
    ResourceBundle,
    ResourceDefinition,
    SchemaDefinition,
    SchemaRef,
)

from ._version import __version__
from .canonical import JsonValue
from .catalogs import EVIDENCE_CONTRACT_VERSION, EVIDENCE_REGISTRY_REF

_SCHEMA_FILES: Mapping[str, str] = {
    "common": "meridian.evidence.common.v1.schema.json",
    "log": "meridian.evidence.log.v1.schema.json",
    "span": "meridian.evidence.span.v1.schema.json",
    "metric_point": "meridian.evidence.metric-point.v1.schema.json",
    "audit": "meridian.evidence.audit.v1.schema.json",
    "lineage": "meridian.evidence.lineage.v1.schema.json",
    "provenance": "meridian.evidence.provenance.v1.schema.json",
    "policy": "meridian.evidence.policy.v1.schema.json",
    "registry_metadata": "meridian.evidence.registry.v1.schema.json",
}


def schema_names() -> tuple[str, ...]:
    return tuple(sorted(_SCHEMA_FILES))


def evidence_schema(name: str) -> Mapping[str, JsonValue]:
    """Load one released Evidence JSON Schema by logical name."""

    try:
        filename = _SCHEMA_FILES[name]
    except KeyError as exc:
        raise KeyError(f"unknown Evidence schema {name!r}") from exc
    packaged = package_resources.files("meridian_storage.evidence").joinpath(
        "contracts", "schemas", filename
    )
    if packaged.is_file():
        content = packaged.read_text(encoding="utf-8")
    else:
        source = Path(__file__).resolve().parents[3] / "contracts" / "schemas" / filename
        content = source.read_text(encoding="utf-8")
    value = json.loads(content)
    if not isinstance(value, Mapping):
        raise ValueError(f"packaged Evidence schema {name!r} must be an object")
    return cast(Mapping[str, JsonValue], value)


class EvidenceSchemaProvider:
    """Core schema-provider entry point for Evidence bootstrap contracts."""

    provider_id = "meridian.evidence"
    provider_contract_version = EVIDENCE_CONTRACT_VERSION

    def load(self) -> ResourceBundle:
        common_ref = SchemaRef("evidence", "meridian", "common", "1.0.0")
        schemas = tuple(
            SchemaDefinition(
                ref=SchemaRef("evidence", "meridian", name, "1.0.0"),
                definition=evidence_schema(name),
                dependencies=(common_ref,)
                if name in {"log", "span", "metric_point", "audit", "lineage", "provenance"}
                else (),
                extensions={"jsonSchemaDraft": "2020-12"},
            )
            for name in schema_names()
        )
        registry_schema = next(item.ref for item in schemas if item.ref.name == "registry_metadata")
        return ResourceBundle(
            provider_id=self.provider_id,
            provider_version=__version__,
            provider_contract_version=self.provider_contract_version,
            namespaces=(NamespaceDefinition("evidence", "meridian", {"owner": "evidence"}),),
            schemas=schemas,
            resources=(
                ResourceDefinition(
                    EVIDENCE_REGISTRY_REF,
                    profile="metadata-registry",
                    schema=registry_schema,
                    required_scope=("tenant",),
                ),
            ),
            extensions={
                "design.hldRevision": 60,
                "design.catalogRevision": 72,
                "schemaCount": len(schemas),
            },
        )


__all__ = ["EvidenceSchemaProvider", "evidence_schema", "schema_names"]
