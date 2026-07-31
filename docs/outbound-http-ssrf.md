<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.
-->

# Outbound HTTP and SSRF

Outbound HTTP calls (peer discovery, Directory Service fetch, OCM protocol
posts) go through `internal/platform/http/client`. The client enforces SSRF
protections before dial and revalidates on redirects.

## Config surface

`[outbound_http]` in TOML maps to `OutboundHTTPConfig`:

| Field | Role |
| ----- | ---- |
| `[outbound_http.ssrf] mode` | `strict` (deny private destinations) or `off` |
| `[outbound_http.ssrf] route_policy` | Named operator allowlist policy |
| `[outbound_http.ssrf] route_policies.*` | Host suffix, CIDR, port rules |
| `timeout_ms`, `connect_timeout_ms` | Client timeouts |
| `max_redirects`, `max_response_bytes` | Safety limits |
| `tls_root_ca_file`, `tls_root_ca_dir` | Outbound TLS trust |
| `proxy_url`, `use_env_fallback` | Proxy routing |

Strict preset uses `ssrf.mode=strict` with deny-by-default private
destinations and defaults `use_env_fallback` to false (opt-in). Set
`use_env_fallback = true` in TOML or
`OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK=true` to opt in to
`HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` when `proxy_url` is not set.
`OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK` is currently the only
supported environment override; it overrides the `use_env_fallback` TOML
key, and the environment layer is the highest precedence (above preset
default, TOML, and CLI flags where they exist; `use_env_fallback` has no
CLI flag).
Operator-declared route policies can allow narrow private
host suffix / CIDR / port combinations for lab setups.

Read [verification-boundary.md](verification-boundary.md) for what strict
SSRF proves and what remains operator-gated.

## Enforcement model

Core logic: `internal/platform/http/client/ssrf.go`.

1. **Public destinations** pass when hostname resolves to public addresses.
2. **Private destinations** require an active named route policy where
   hostname suffix, resolved IP/CIDR, and destination port all match.
3. **IP literals** are blocked under active route policies
   (`allow_ip_literals=true` is rejected at config load in that lane).
   Outside that lane, IP literals still need `allow_ip_literals=true`
   plus matching CIDR and port rules.
4. **localhost** hostnames are always blocked.

The same checks run for initial URL preflight and redirect targets.

## Discover helper behavior

`/ocm-aux/discover` uses the configured discovery client. When SSRF blocks a
target:

- HTTP status `403`
- JSON `success: false`, `reasonCode: "ssrf_blocked"`
- User-facing `error` text without internal CIDR or IP details

Proof: `tests/integration/ocmaux_discover_normalization_test.go`
(`TestOCMAuxDiscover_SSRFBlockedFriendlyReason`).

```sh
go test ./tests/integration/... -run TestOCMAuxDiscover_SSRFBlocked
```

Unit-level discover error mapping:
`internal/components/ocmaux/handler_discover_contract_test.go`.

## Other outbound callers

| Caller | Typical target |
| ------ | -------------- |
| `internal/components/ocm/discovery` | Peer `/.well-known/ocm` |
| `internal/components/ocm/directoryservice` | Directory Service HTTPS GET |
| `internal/components/ocm/outbound` | OCM protocol POST to peers |

All share the same HTTP client configuration from wiring.

## Proxy interaction

When `proxy_url` is set it takes precedence over environment proxy
variables. Under the strict preset, `use_env_fallback` defaults to
false (opt-in). Set `use_env_fallback = true` in TOML or
`OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK=true` to opt in to
`HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` when `proxy_url` is not
set. Under the strict lane, the proxy host is treated
as operator-trusted
(private/loopback proxy addresses allowed). Destination SSRF checks still
apply to the final target.

## Verification

```sh
go test ./internal/platform/http/client/...
go test ./tests/integration/... -run TestOCMAuxDiscover_SSRF
go test ./tests/ca_pool/...
```

Architecture and integration tests under strict posture exercise blocked
private destinations and explicit allowlist positives. See
[verification-boundary.md](verification-boundary.md).

## Related docs

- [configuration.md](configuration.md) - outbound_http section
- [invite-wayf-and-accept.md](invite-wayf-and-accept.md) - discover in WAYF
- [directory-service-and-ocm-aux.md](directory-service-and-ocm-aux.md) -
  Directory Service fetch
