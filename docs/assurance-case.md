<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict,
WebDAV-centered subset of the protocol.
-->

# Assurance case

This is the project's assurance case: it justifies why the security
requirements in [security-requirements.md](security-requirements.md) are met.
It is a lightweight, claims-and-evidence style assurance case, not a full
formal notation.

## Security requirements (claims)

1. **R1: Transport security.** Inbound and outbound HTTP use TLS by default.
2. **R2: Forward secrecy.** TLS provides perfect forward secrecy.
3. **R3: Password storage.** Local identity passwords are stored as salted
   `argon2id` hashes.
4. **R4: Outbound request confinement.** Outbound HTTP is constrained by an
   SSRF allowlist.
5. **R5: Input validation.** Untrusted inputs are validated with an
   allowlist and invalid inputs are rejected.
6. **R6: Cryptographic randomness.** Keys and nonces use `crypto/rand`.
7. **R7: No known unpatched vulnerabilities.** Medium and higher findings from
   static and dynamic analysis are fixed.

## Architecture context

OpenCloudMesh Go is a standalone server-side OCM peer. The security-relevant
subsystems are:

- `internal/platform/http/tls/` - TLS configuration and certificate
  verification.
- `internal/components/identity/` - local identity and password hashing.
- `internal/wiring/` and `internal/services/api/` - input validation.
- Outbound HTTP - SSRF allowlist enforcement. See
  [outbound-http-ssrf.md](outbound-http-ssrf.md).

## Evidence

| Requirement | Evidence | Verification |
| ----------- | -------- | ------------ |
| R1 Transport security | `internal/platform/http/tls/tls.go` uses Go `crypto/tls` with certificate verification on by default | `go test ./internal/platform/http/tls/...` |
| R2 Forward secrecy | TLS cipher suites use ECDHE | `go test ./tests/ca_pool/...` |
| R3 Password storage | `internal/components/identity/auth.go` stores `argon2id` hashes | `go test ./internal/components/identity/...` |
| R4 Outbound confinement | SSRF allowlist on outbound HTTP | `go test ./tests/integration/... -run TestOCMAuxDiscover_SSRF` |
| R5 Input validation | `internal/wiring/resolve_inputs.go`, `internal/components/ocm/discovery/validate.go`, `internal/components/ocm/invites/acceptance_validate.go` | `go test ./internal/wiring/... ./internal/components/ocm/discovery/... ./internal/components/ocm/invites/...` |
| R6 Crypto randomness | `crypto/rand` used for keys and nonces | `go test ./internal/components/identity/...` |
| R7 No unpatched vulns | `govulncheck`, `gosec`, CodeQL gates in CI | `nu`/CI: `ci-security-govulncheck.yml`, `ci-security-gosec.yml`, `security-codeql.yml` |

## Continuous assurance

The evidence above is checked on every change, not once:

- `gosec`, CodeQL, `govulncheck`, and `golangci-lint` run on every push and
  pull request.
- The Go race detector (`go test -race`) runs in CI as dynamic analysis.
- Dependabot monitors dependencies for known vulnerabilities.

## Limits of this assurance case

This case justifies the security requirements that are in scope today. It
does **not** claim:

- broad peer interoperability (see [verification-boundary.md](verification-boundary.md));
- a supported release line (see [SECURITY.md](../SECURITY.md));
- that the software is safe against all possible misuse or misconfiguration.

## Related docs

- [security-requirements.md](security-requirements.md) - the requirements this case justifies
- [outbound-http-ssrf.md](outbound-http-ssrf.md) - SSRF allowlist
- [verification-boundary.md](verification-boundary.md) - what is and is not verified
- [../SECURITY.md](../SECURITY.md) - vulnerability reporting
