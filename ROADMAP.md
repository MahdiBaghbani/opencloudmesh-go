<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict,
WebDAV-centered subset of the protocol.
-->

# Roadmap

This roadmap describes what OpenCloudMesh Go intends to do, and explicitly
what it does **not** intend to do, for roughly the next year. It is a living
document: the [issue tracker](https://github.com/MahdiBaghbani/opencloudmesh-go/issues)
is the source of truth for current status, and this page is updated as
priorities move.

## What this project is

A runnable Open Cloud Mesh (OCM) peer in Go that implements a strict,
WebDAV-centered subset of the OCM protocol. See
[docs/verification-boundary.md](docs/verification-boundary.md) for the exact
contract that is verified.

## In scope (next ~12 months)

- **First signed release.** Publish the first GitHub Release from the existing
  `release-binary.yml` pipeline, with build provenance attached as a release
  asset so the OpenSSF Scorecard Signed-Releases check passes. See
  [.github/workflows/release-binary.yml](.github/workflows/release-binary.yml).
- **Supply-chain hardening.** Keep the OpenSSF Scorecard at or above its
  current 8.8/10, keep `gosec`, `govulncheck`, CodeQL, and dependency-review
  gates green, and keep all actions pinned with
  [.github/action-pins.yml](.github/action-pins.yml).
- **Test coverage.** Raise statement coverage toward 80% for the strict
  contract and add a coverage gate so coverage cannot silently regress.
- **Reproducible builds.** Make the binary build bit-for-bit reproducible and
  verify it in CI.
- **Strict WebDAV subset correctness.** Tighten the invite, discovery, and
  route-policy behavior and the tests that prove them, without expanding the
  protocol surface.
- **Crypto agility.** Make the cryptographic primitives (TLS version floor,
  password hashing parameters) configurable so operators can react quickly if
  an algorithm is weakened.
- **Docs.** Keep [docs/](docs/) consistent with the current version and grow
  the assurance case as the security story matures.

## Out of scope (next ~12 months)

- **Broad peer interoperability.** The project does not aim to interoperate with
  arbitrary OCM peers or to implement the full OCM specification. It targets a
  strict WebDAV-centered subset. See
  [docs/verification-boundary.md](docs/verification-boundary.md).
- **A supported release line.** Until the first signed release ships, there
  is no supported version matrix. See [SECURITY.md](SECURITY.md).
- **A second maintainer.** The project is solo-maintainer today. Growing a
  second maintainer is desirable for continuity (see
  [GOVERNANCE.md](GOVERNANCE.md)) but is not committed on a timeline.

## Status

Git tags `v1.0.0` and `v1.1.0` exist but are unsupported lines with no
release artifacts or maintenance commitment. The first supported release will
be the one produced by the signed-release work above.

## Related docs

- [GOVERNANCE.md](GOVERNANCE.md) - decision-making and roles
- [docs/verification-boundary.md](docs/verification-boundary.md) - what is and is not verified
- [SECURITY.md](SECURITY.md) - supported versions and reporting
