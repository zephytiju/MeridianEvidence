<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

## 1.0.2

- Admit the public Core 1.1.0 / Semantics 2.0.1 closure using bounded API dependencies.
- Separate the exact hash-verified validation lock from runtime compatibility metadata.
- Preserve Evidence Data, operations, atomic placement checks and normalization fingerprints.

## 1.0.1

- Resolve against released Core 1.0.1 and Semantics 2.0.0; refresh compatibility digests and SBOM inputs.
- Verify installed-package compatibility while preserving Evidence V1 schemas, operations, fingerprints, errors, scope/atomic requirements, and OTel behavior.

## 1.0.0 - 2026-08-25

- Added the complete Meridian V1 Evidence Catalog provider and schema provider.
- Added deterministic telemetry, audit, lineage, provenance, policy, retention, and query helpers.
- Added explicit operation hooks with scope, trace, and provenance propagation.
- Added a bounded recursion-safe low-level OTel bridge.
- Added language-neutral contracts, conformance fixtures, reproducible packaging, SBOM generation,
  CI, and gated release automation.
