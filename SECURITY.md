<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
-->

# Security Policy

OpenCloudMesh Go is a solo-maintainer Go OCM peer focused on a strict,
WebDAV-centered subset of the protocol. This document explains how to report
security issues and what is in scope.

## Supported Versions

There is no supported release line yet. The project has not published any
GitHub Releases. Git tags `v1.0.0` and `v1.1.0` exist but are unsupported
lines with no release artifacts or maintenance commitment. Do not assume a
supported version matrix; report issues against the branch or commit you tested.

## Reporting a Vulnerability

Use GitHub Private Vulnerability Reporting (PVR) as the primary channel. On
this repository, open the **Security** tab and click **Report a vulnerability**.
Do not use email-only reporting or expect a published PGP key.

We acknowledge reports on a best-effort basis. There is no hard triage SLA.
For valid issues, we aim for coordinated disclosure with a flexible window of
about 90 days. That target is approximate, not a rigid deadline; timing may
vary with severity, complexity, and maintainer availability.

## Scope

Reports are in scope when they affect security behavior in this repository,
including:

- Authentication and session handling
- Cryptography and key material handling
- HTTP Message Signatures (RFC 9421)
- JWKS publication and verification
- Token exchange
- WebDAV bearer access
- Invite and trust flows
- SSRF protection for outbound HTTP
- TLS configuration and certificate handling

This scope applies across all server modes, including `mode=dev`. Intentional
relaxations in dev mode are not blanket out-of-scope. Please still report
them, but understand they may receive lower priority than the same class of
issue in `mode=strict`.

## Security Posture

For deployments and security testing, prefer `mode=strict` as the default and
recommended posture. `mode=dev` relaxes several protections and is intended for
local development only. Do not run dev mode on untrusted networks or expose it
to the public internet.

## Automated Scanning

The project runs `govulncheck` in CI to scan existing dependencies for known
vulnerabilities. It is a blocking check that fails CI on confirmed
vulnerabilities. Scanning of NEW dependencies introduced by a pull request is
a separate, required gate; see the Dependency-Review Gate section below.
Scorecard is report-only; see the Scorecard Posture section below. These scans
do not guarantee a fix timeline or SLA for reported vulnerabilities.

## Signed Releases

Scorecard's Signed-Releases check is expected to fail because GitHub Artifact
Attestations live in the attestations API, not in release assets named
`*.sig`, `*.asc`, or `*.intoto.jsonl` that Scorecard scans. This failing check
is accepted as non-required. Provenance is verifiable with:

```bash
gh attestation verify oci://ghcr.io/mahdibaghbani/opencloudmesh-go:v1.2.3 \
  --repo MahdiBaghbani/opencloudmesh-go
```

See upstream Scorecard issues
[#4667](https://github.com/ossf/scorecard/issues/4667) and
[#4080](https://github.com/ossf/scorecard/issues/4080).

## Scorecard Posture

OpenSSF Scorecard runs on master push and on a weekly schedule, publishes
results to the OpenSSF API, and uploads SARIF to this repository's GitHub
Security tab.

It is deliberately report-only: it is NOT a merge gate and NOT run per-PR,
because it is a holistic repo-level assessment whose checks do not vary per
pull request.

It includes intentionally-unmet checks for a solo-maintainer repo. Code-Review
(0 approvals, reviews disabled) is one of these and is reflected in the
open-alert count below. The Signed-Releases exception (GitHub Artifact
Attestations live in the attestations API, not release assets Scorecard scans)
is tracked separately in the Signed Releases section above and is not part of
the open-alert count below. These are accepted, not gating.

The score is raised by targeted fixes, not by gating. Two such fixes:
Token-Permissions (workflow token permissions are scoped to least privilege)
and Pinned-Dependencies (Docker base images are pinned by digest).

As of 2026-08-06, per the GitHub Security tab (code-scanning alerts,
tool=Scorecard), there are 20 open Scorecard alerts (16 high, 3 medium,
1 low): Token-Permissions 14, Pinned-Dependencies 3, CII-Best-Practices 1,
Code-Review 1, Vulnerabilities 1. That count is a pre-merge snapshot: the
token-permission scoping and base-image digest pinning target the
Token-Permissions and Pinned-Dependencies categories, so once those changes
merge and Scorecard re-runs, those two counts are expected to drop. The
Vulnerabilities alert is Scorecard's report-only check and is separate from
the blocking govulncheck CI job; see Automated Scanning above.

## Dependency-Review Gate

The dependency-review action runs on every pull_request against master and IS
a required merge gate (one of the required checks).

Configuration: fail-on-severity moderate (severity levels are low, moderate,
high, critical; the gate fails on vulnerabilities at moderate or higher, so
low-severity findings do not block), fail-on-scopes
runtime, development, unknown (defense-in-depth so dev/unknown-scope vulns do
not pass silently), plus a license allowlist.

Contrast with Scorecard: dependency-review is per-PR and blocking; Scorecard
is repo-level and report-only.
