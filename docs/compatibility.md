<!-- SPDX-License-Identifier: Apache-2.0 -->

# Compatibility

Version 1.0.2 requires Python 3.12 or newer, Core `>=1.1.0,<2`, and Semantics
`>=2.0.1,<3`. These are public API compatibility bounds, not deployment release selections.
Core 1.1.0 is the tested floor for the repaired descriptor/runtime contracts; Semantics 2.0.1
is the first 2.x release with a normally resolvable Core 1.1.0 closure. Major upper bounds
preserve potentially breaking Core SPI and Semantics Schema/Operation boundaries.

Evidence uses the released Core Expression, Operation, CatalogManifest, CapabilityRequirement,
ResourceRef, SchemaBundle and context/result types. Its Evidence operation contracts and Data
schemas remain 1.0.0/v1. No runtime implementation change or stored-Data migration is needed.
The manifest package coordinate changes to 1.0.2, so deployments must explicitly update their
selected package lock and corresponding manifest fingerprint. Serialized append/query operations
and their fingerprints must still match the released normalization golden without regeneration.

`requirements-validation.lock` separately pins Core 1.1.0 and Semantics 2.0.1, the entire runtime
dependency closure, with public wheel and sdist SHA-256 values. CI and release jobs install this
lock with hash verification, then normally resolve the owned package and run `pip check`.
The installed-wheel check verifies the exact selected validation versions. These assertions are
release-integrity gates, never runtime compatibility predicates. Other combinations remain
unverified until tested; a compatible range alone is not evidence of engine conformance.

The existing unit, property, conformance and Core integration suite covers audit/lineage policy,
OTel fidelity, redaction, golden schemas, atomic capability requirements and cross-Binding
rejection. This provider-neutral repository has no real-engine persistence gate; released Adapter
and final composition conformance own physical commit/rollback evidence. No engine behavior is
claimed by this metadata repair, and no existing gate is skipped or weakened.

The implementation conforms to Meridian HLD rev 60 and Catalogs and Public Interfaces rev 72
§5.7. Those revisions explicitly assign the consumer-facing observability facade to the separate
`meridian-storage-plugin-observability` package and state that Core has no `Meridian.telemetry()`
method.

Compatibility rules:

- audit, lineage, provenance, and telemetry remain profiles of the one Evidence Catalog;
- the Core Evidence method registry remains exhaustive;
- mapping-first Expressions and serialized Core Operations are authoritative;
- query values are provider-neutral mappings compatible with the separately released shared Query
  library contract;
- optional future WORM and military/national-security profiles may use namespaced extensions but
  are not implemented by V1; and
- no compatibility promise covers Adapter-private storage, provider clients, physical identifiers,
  or deployment configuration.
