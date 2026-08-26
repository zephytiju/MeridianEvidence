<!-- SPDX-License-Identifier: Apache-2.0 -->

# Releasing

1. Ensure `main` is green and version, changelog, public API, compatibility, and contract ledgers
   agree.
2. Run all README quality gates and build twice with one `SOURCE_DATE_EPOCH`.
3. Compare and verify the artifacts, generate the SPDX 2.3 SBOM, and smoke-install the wheel with
   released dependencies.
4. Create and push the signed or annotated `vX.Y.Z` tag on a commit reachable from `main`.
5. GitHub Actions repeats every gate, attests the artifacts, and creates the GitHub release.

The first PyPI publication is an owner-assisted namespace and trusted-publisher gate. Keep the
repository variable `PYPI_TRUSTED_PUBLISHING_ENABLED` unset or false until ownership and the `pypi`
environment are established. After that one-time setup, tagged releases publish through GitHub OIDC;
never bypass MFA, tokens, namespace ownership, or branch protection.
