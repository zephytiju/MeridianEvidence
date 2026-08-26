<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing

Changes must preserve the exactly-five-Catalog boundary, mapping-first public syntax, stable error
envelopes, provider neutrality, and the repository's one-package scope. An architecture or public
interface change requires approved design write-back before implementation.

Install `.[test]`, then run formatting, lint, strict typing, contract verification, and the full
coverage suite shown in the README. Add deterministic fixtures for contract changes and update the
public API or compatibility ledger when applicable. Never commit credentials, endpoint values,
physical storage identifiers, or generated build artifacts.
