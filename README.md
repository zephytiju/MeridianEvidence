<!-- SPDX-License-Identifier: Apache-2.0 -->
# meridian-storage-evidence

`meridian-storage-evidence` is the single Python distribution implementing the Meridian V1
`evidence` Catalog. It provides provider-neutral audit, lineage, provenance, telemetry, policy,
and OpenTelemetry bridge contracts without selecting an Adapter, Engine, endpoint, Collector,
or deployment topology.

The repository is licensed under Apache License 2.0. Its public API targets
`meridian-storage-core==1.0.0` and `meridian-storage-semantics==1.0.0`.

The authoritative design boundary is Meridian HLD revision 60 and Meridian Catalogs and Public
Interfaces revision 72. The separate `meridian-storage-plugin-observability` package owns the
consumer-facing tracer, meter, and logger convenience facade; Core does not expose a
`Meridian.telemetry()` method.

