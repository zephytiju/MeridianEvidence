<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contracts

## Catalog manifest

The V1 `evidence` Catalog exposes exactly:

| Method | Operation contract | Read only | Idempotency |
| --- | --- | --- | --- |
| `append` | `meridian.evidence.append` | no | conditional |
| `create_resource` | `meridian.evidence.create_resource` | no | always |
| `publish_schema` | `meridian.evidence.publish_schema` | no | always |
| `query` | `meridian.evidence.query` | yes | always |

The checked-in [Catalog ledger](../contracts/catalogs/meridian-evidence-catalog.v1.json) is compared
exactly with the provider manifest in every CI run. Core rejects missing or additional methods.

## Stored record format

Typed helpers serialize `meridian-evidence-data.v1`. Common fields include tenant and scope, OTel
resource and instrumentation scope, event and observed timestamps, ingestion identity, source
protocol version, typed attributes, provenance, optional subject, optional correlation, and
namespaced extensions.

- Logs preserve severity, typed body, flags, and optional trace/span identity.
- Spans preserve trace relationships, name, kind, interval, status, attributes, events, and links.
- Metric points preserve identity, unit, type, temporality, monotonicity, interval, numeric or
  histogram value, dimensions, flags, and exemplars.
- Audit records preserve action, actor/principal, occurrence time, request/Operation identity,
  outcome, permitted change metadata, policy labels, optional subject, correction link, and safe
  Binding/Adapter provenance. Unrestricted request/response bodies are rejected.
- Lineage records preserve activity and execution identity, immutable input/output references,
  Schema/model versions, Query fingerprints, source revisions, digests, actor, timestamps,
  Operation Context scope, checkpoints, and namespaced metadata.
- Provenance records preserve an entity, immutable sources, generating activity, and actor.

Draft 2020-12 JSON Schemas live in `contracts/schemas`. Language-neutral valid and invalid fixtures
live in `contracts/conformance`.

## Policy

Policy is a provider-neutral input for required fields, redaction, atomicity, access, retention,
cardinality, record limits, and queue behavior. Policy normalization is deterministic. Sensitive
values may be rejected, replaced, or dropped. `CardinalityBudget` stores only SHA-256 fingerprints
of observed key/value combinations and never raw sensitive values.

## Errors

Every package failure subclasses a stable Core error category and emits a
`MERIDIAN_EVIDENCE_*` code. The envelope may add a requirement, sorted logical references, and a
policy label. It never includes credentials, endpoint details, physical names, or unrestricted
request/response bodies. The exact export and error ledgers are in
`contracts/public-api/meridian-evidence.v1.json`.
