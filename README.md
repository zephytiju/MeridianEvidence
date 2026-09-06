<!-- SPDX-License-Identifier: Apache-2.0 -->

# meridian-storage-evidence

`meridian-storage-evidence` is the single Python distribution implementing the Meridian V1
`evidence` Catalog. It provides provider-neutral audit, lineage, provenance, telemetry, policy,
query-helper, and low-level OpenTelemetry bridge contracts. It never selects an Adapter, Engine,
endpoint, Collector, or deployment topology.

The package is licensed under Apache License 2.0 and targets Python 3.12 or newer. Its released
dependencies are pinned to `meridian-storage-core==1.0.1` and
`meridian-storage-semantics==2.0.0`.

## Install

```console
python -m pip install meridian-storage-evidence==1.0.1
```

## Mapping-first Catalog API

Core discovers `EvidenceCatalogProvider` through the `meridian_storage.catalogs` entry-point.
Consumer code uses the same mapping-first syntax as every other Meridian Catalog:

```python
evidence = meridian.catalog("evidence")

expression = evidence.append(
    resource="runtime.logs",
    data={
        "severity": "INFO",
        "body": "worker ready",
        "attributes": {"worker": worker_name},
    },
)
meridian.execute(expression)

rows = meridian.execute(
    evidence.query(
        resource="runtime.logs",
        where={"severity": {"eq": "INFO"}},
        limit=50,
    ),
).data
```

The exhaustive V1 surface is `append`, `create_resource`, `publish_schema`, and `query`. Audit,
lineage, provenance, and telemetry are profiles inside the one `evidence` Catalog—not additional
Catalog names.

## Typed helpers and operation hooks

Mapping inputs remain authoritative. Typed records add validation and deterministic serialization:

```python
from datetime import UTC, datetime

from meridian_storage.evidence import EvidenceMetadata, LogRecord

record = LogRecord(
    severity="INFO",
    body="worker ready",
    metadata=EvidenceMetadata(
        event_time=datetime.now(UTC),
        observed_time=datetime.now(UTC),
        tenant="tenant-a",
        scope={"environment": "production"},
    ),
)
expression = evidence.append(resource="runtime.logs", data=record)
```

`OperationEvidenceHooks` builds explicit append plans from Core `Operation`, `OperationContext`,
`OperationResult`, and normalized failures. It propagates request, execution, tenant, scope, trace,
and safe Adapter provenance without copying unrestricted request/response bodies. Required atomic
audit plans must pass `EvidenceHookPlan.validate_atomic_resolution` before publication or startup.

## OpenTelemetry boundary

`OTelEvidenceBridge` preserves OTel log, span, and metric fields and supplies a bounded queue,
timeouts, recursion suppression, and non-recursive health counters. The separate public
`meridian-storage-plugin-observability` package owns consumer-facing tracers, meters, structured
loggers, exporter wiring, and process-wide provider installation. Core deliberately has no
`Meridian.telemetry()` method.

## Policy and retention

`EvidencePolicy` handles required fields, deterministic redaction/drop/rejection, record and
attribute bounds, distinct-value cardinality budgets, access-scope inputs, atomicity, queue-failure
policy, and logical retention intent. `RetentionPolicyInput` does not configure storage, delete
Data, enable WORM, or implement a military/national-security profile. Those remain deployment and
future-profile concerns.

## Architecture boundary

Meridian has exactly five Catalogs: structured, object, cache, evidence, and streaming. Evidence
persistence belongs to independently released Adapters. Collector deployment, OTLP routing,
storage placement, retention execution, recovery, and lifecycle belong to MeridianConstructs and
deployment IaC. Public values contain logical Resource references only; they never expose provider
credentials, endpoints, or physical names.

The implementation authority is Meridian HLD revision 60 and Meridian Catalogs and Public
Interfaces revision 72, section 5.7. See [architecture](docs/architecture.md),
[contracts](docs/contracts.md), and [compatibility](docs/compatibility.md).

## Development

```console
python -m pip install '.[test]'
ruff format --check src tests scripts
ruff check src tests scripts
mypy src
python scripts/verify_contracts.py
pytest --cov=meridian_storage.evidence --cov-report=term-missing
python -m build --no-isolation
python scripts/verify_artifacts.py dist
```

Release builds are made twice under one `SOURCE_DATE_EPOCH`, compared byte-for-byte, verified,
described by a deterministic SPDX 2.3 SBOM, and attested by GitHub Actions.
