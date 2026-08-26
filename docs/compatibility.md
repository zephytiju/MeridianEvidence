<!-- SPDX-License-Identifier: Apache-2.0 -->

# Compatibility

Version 1.0.0 requires Python 3.12 or newer and exactly the released
`meridian-storage-core==1.0.0` and `meridian-storage-semantics==1.0.0` contracts. The source,
wheel, and sdist evidence for those dependencies is pinned in `compatibility.json`.

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
