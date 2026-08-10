<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict,
WebDAV-centered subset of the protocol.
-->

# Cryptographic algorithm agility

OpenCloudMesh Go is designed so the cryptographic algorithms it relies on can be
changed without rewriting the server. This page records where algorithms are
selectable today and how they are updated.

## HTTP message signatures

OCM peers authenticate requests with HTTP message signatures
([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html)). The set of signature
algorithms the server will accept and emit is a configuration value, not a
compile-time constant.

- Config key: `signature.allowed_algorithms`
- Defaults (from `DefaultSignatureConfig` in
  `internal/platform/config/defaults.go`): Ed25519, ECDSA P-256 SHA-256,
  RSA PKCS1 SHA-256, and the rest of `sigalg.DefaultAllowed()`.
- Normalization and validation: `NormalizeSignatureAllowedAlgorithms` in
  `internal/platform/config/loader.go` canonicalizes JOSE aliases (for example
  `ES256`), rejects symmetric algorithms such as HMAC, rejects unknown
  entries, and de-duplicates while preserving first-seen order.

To switch algorithms, an operator changes `signature.allowed_algorithms` in the
config and restarts the server. No code change or recompilation is required.

## RSA modulus floor

JWK verification applies a stricter-than-OCM local policy to RSA keys:
`signature.min_rsa_modulus_bits` defaults to 2048. OCM does not define an RSA
bit minimum, so lowering this setting can interoperate with legacy peers using
1024-bit RSA keys that remain OCM-valid.

## TLS

The server's TLS configuration lives in `internal/platform/http/tls/tls.go`.

- Minimum TLS version: TLS 1.2, the secure floor. Insecure protocols (SSLv3
  and earlier, TLS 1.0/1.1) are not offered.
- Cipher suites: Go's `crypto/tls` secure defaults. Go updates the default
  cipher suite list and removes weak algorithms as the toolchain advances, so
  the server picks up those changes by bumping the Go toolchain pinned in
  `go.mod`.

## Credential and key storage

Signing keys and any authentication material are loaded from files referenced
by configuration (for example `signature.key_path`), separate from the rest of
the configuration and from logs. Operators can rotate or replace keys by
replacing the file and restarting; no recompilation is needed.

## Updating algorithms

When an algorithm is deprecated or broken:

1. Remove it from `signature.allowed_algorithms` in the deployment config, or
   narrow the default set in `DefaultSignatureConfig` and
   `sigalg.DefaultAllowed()` for a new release.
2. For TLS, bump the Go toolchain version pinned in `go.mod` so `crypto/tls`
   drops the weak algorithm from its defaults.
3. Ship a release and update the deployment.

The fuzz targets in `internal/platform/crypto/sigparams`,
`internal/platform/crypto/jwks`, and `internal/components/ocm/spec` exercise the
signature and JSON parsing paths so regressions in algorithm handling surface
in CI.
