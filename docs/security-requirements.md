<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict,
WebDAV-centered subset of the protocol.
-->

# Security requirements

This document states what users can and cannot expect in terms of security
from OpenCloudMesh Go. It is the software's security requirements statement;
[SECURITY.md](../SECURITY.md) covers how to report vulnerabilities.

## What the software is

A server-side OCM protocol peer. It is not a library that is embedded into
other applications; it runs as a standalone service. See
[architecture.md](architecture.md).

## What you can expect

- **Transport security.** Inbound and outbound HTTP use TLS by default. The
  TLS stack is the Go `crypto/tls` stdlib, which performs certificate
  verification by default and rejects invalid certificates. See
  [../internal/platform/http/tls/tls.go](../internal/platform/http/tls/tls.go).
- **Forward secrecy.** TLS cipher suites provide perfect forward secrecy via
  ECDHE.
- **Password storage.** Local identity passwords are stored as salted
  `argon2id` hashes, not plaintext. See
  [../internal/components/identity/auth.go](../internal/components/identity/auth.go).
- **Outbound request confinement.** Outbound HTTP is constrained by an SSRF
  allowlist so the server cannot be driven to arbitrary internal or public
  endpoints. See [outbound-http-ssrf.md](outbound-http-ssrf.md).
- **Input validation.** Inputs from untrusted sources are validated with an
  allowlist and invalid inputs are rejected. See
  [../internal/wiring/resolve_inputs.go](../internal/wiring/resolve_inputs.go),
  [../internal/components/ocm/discovery/validate.go](../internal/components/ocm/discovery/validate.go),
  and
  [../internal/components/ocm/invites/acceptance_validate.go](../internal/components/ocm/invites/acceptance_validate.go).
- **Cryptographic randomness.** Cryptographic keys and nonces are generated
  with `crypto/rand`.
- **Static and dynamic analysis.** `gosec`, CodeQL, `govulncheck`, and
  `golangci-lint` run on every change, and the Go race detector runs in CI.

## What you cannot expect

- **No supported release line.** There is no supported version matrix yet.
  Do not assume a release is patched; report issues against the branch or
  commit you tested. See [../SECURITY.md](../SECURITY.md).
- **No hard SLA.** Vulnerability reports are acknowledged on a best-effort
  basis by a solo maintainer. There is no hard triage or fix SLA. See
  [../SECURITY.md](../SECURITY.md).
- **No broad peer interoperability.** The software implements a strict
  WebDAV-centered subset of OCM. It does not claim to be safe against all
  peers or all protocol variants. See
  [verification-boundary.md](verification-boundary.md).
- **No algorithm agility today.** Cryptographic primitives are fixed to the
  Go stdlib defaults and cannot yet be swapped at runtime. Configurable
  crypto is on the roadmap, not shipped. See [../ROADMAP.md](../ROADMAP.md).
- **No guarantee against all misuse.** Hardening reduces but does not
  eliminate the risk that an operator misconfiguration exposes a vulnerability.

## Related docs

- [../SECURITY.md](../SECURITY.md) - vulnerability reporting and response
- [outbound-http-ssrf.md](outbound-http-ssrf.md) - SSRF allowlist
- [verification-boundary.md](verification-boundary.md) - what is and is not verified
