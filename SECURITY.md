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

The project may run `govulncheck` and other automated dependency scanning in
CI. Those results are informational. They are not a hard gate and do not
guarantee a fix timeline or SLA for reported vulnerabilities.
