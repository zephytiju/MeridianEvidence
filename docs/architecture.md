<!-- SPDX-License-Identifier: Apache-2.0 -->

# Architecture

This repository owns one package and one of Meridian's exactly five Catalogs: `evidence`. It is
implemented against Meridian HLD rev 60 and Catalogs and Public Interfaces rev 72 §5.7.

## Responsibilities

The package owns:

- the four Core-registered Evidence Expressions and normalized Operations;
- provider-neutral log, span, metric-point, audit, lineage, provenance, and policy schemas;
- deterministic typed records and append-only correction/checkpoint contracts;
- explicit query/write operation evidence hooks and OTel correlation propagation;
- engine-neutral Evidence query helpers;
- a low-level bounded OTel bridge with recursion suppression and health counters; and
- logical retention and future-profile extension inputs.

It does not own Evidence persistence, Binding resolution, transaction execution, authorization at
an application API, a Collector, exporters, deployment topology, storage placement, retention
execution, WORM, or national-security controls.

## Operation flow

1. A consumer creates an `Expression` through `meridian.catalog("evidence")` or an optional typed
   helper.
2. `EvidenceCatalogProvider` validates the mapping and emits an immutable Core `Operation` with
   only logical Resource references and capability requirements.
3. Core resolves a deployment-selected Binding and Adapter. The Adapter persists or queries Data
   and returns a normalized Core result.
4. Explicit operation hooks may build audit and lineage append plans from `OperationContext` and
   safe result provenance. Hooks suppress recursion for Evidence Operations.

Audit and lineage Data are append-only. A correction is a new audit record referencing the prior
identity. A long-running lineage activity appends a start, idempotent checkpoints, and a final
completion or failure.

## Atomic evidence

Required atomic evidence is valid only when all participating logical Resources resolve to one
Binding with the required transaction Capability. `EvidenceHookPlan` exposes the participating
Resources and validates opaque resolution facts. It never reads a Binding or leaks physical
configuration. A failed required audit aborts its transaction; a failed lineage checkpoint remains
incomplete and retryable.

## OTel split

`OTelEvidenceBridge` is deliberately lower-level than an observability SDK. It maps OTel fields to
ordinary Evidence append Expressions and bounds publication. The independently released
`meridian-storage-plugin-observability` owns tracer/meter/logger convenience surfaces and singleton
provider installation. Endpoint, protocol, TLS, queue sizing, exporter, and Collector topology are
deployment configuration.
