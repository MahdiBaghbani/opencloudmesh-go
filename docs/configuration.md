<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.
-->

# Configuration

How the server loads configuration, what presets mean, and where to find
example TOML files.

## Loading order

Effective configuration is resolved in this order (later wins):

1. **Preset bundle** - selected by `mode` (`strict`, `dev`, or `validator`)
2. **TOML file** - path from `-config` or `CONFIG` env in containers
3. **CLI flags** - overrides from `cmd/opencloudmesh-go/main.go`

When no config file is provided and `-mode` is not set, the effective mode
defaults to `strict` (`--mode` flag > `mode` in config file > default
`strict`). The loader starts from the matching preset bundle, then overlays
TOML and CLI values.

The binary entrypoint is `cmd/opencloudmesh-go/main.go`. Notable CLI flags:

| Flag | Purpose |
| ---- | ------- |
| `-config` | TOML file path |
| `-mode` | Preset bundle (`strict`, `dev`, or `validator`) |
| `-listen` | Listen address |
| `-public-origin` | Public origin URL |
| `-external-base-path` | External base path prefix |
| `-token-exchange-path` | Token exchange path under `/ocm/` |
| `-logging-level` | `trace`, `debug`, `info`, `warn`, `error` |
| `-admin-username` / `-admin-password` | Bootstrap admin credentials |

Implementation: `internal/platform/config/loader.go` and `presets.go`.

## Preset bundles

Presets are convenience entry points, not the sole authority for runtime
posture. Effective behavior also depends on the signature, transport, and
trust axes.

| Mode | Intent |
| ---- | ------ |
| `strict` | Production-safe defaults |
| `dev` | Local development; more permissive transport and logging |
| `validator` | Federation validator; statistics, trusted proxies; public anonymous scan (10/60, SSRF-guarded), including passive-only |

## Major config sections

TOML sections map to `internal/platform/config.Config`:

| Section | Role |
| ------- | ---- |
| `mode` | Preset bundle selector |
| `public_origin`, `listen_addr`, `external_base_path` | Identity and binding (see [identity-and-public-origin.md](identity-and-public-origin.md)) |
| `[server]` | Trusted proxies |
| `[statistics]` | Federation statistics (`enabled`; required in validator mode) |
| `[validator]` | Federation validator session, probe, and `[validator.active] enabled` |
| `[tls]` | TLS mode (selfsigned, static, acme, ...) |
| `[outbound_http]` | Outbound client, SSRF, proxy, TLS roots (see [outbound-http-ssrf.md](outbound-http-ssrf.md)) |
| `[http.services.ui.wayf]` | WAYF UI and `invite-wayf` discovery (see [invite-wayf-and-accept.md](invite-wayf-and-accept.md)) |
| `[http.services.ui.invite_accept]` | Accept-invite UI route and invite discovery fields (see [invite-wayf-and-accept.md](invite-wayf-and-accept.md)) |
| `[peer_trust]` | Directory Service trust groups, membership policy, and cache (see [directory-service-and-ocm-aux.md](directory-service-and-ocm-aux.md)) |
| `[signature]` | HTTP signature key, label, timing, and algorithm settings; `allowed_algorithms` gates inbound verify and outbound `SignRequest` (default: ed25519 plus ECDSA P-256/P-384 and RSA PKCS1-v1_5 SHA-256/384/512; JOSE aliases normalize at load) |
| `[token_exchange]` | Token exchange endpoint settings |
| `[logging]` | Log level |
| `[cache]` | Cache driver selection |
| `[persistence]` | Store backend (memory, json, sqlite, mirror) |
| `[http]` | Per-service HTTP limits |

The strict preset defaults `[persistence]` to sqlite with data stored under
`.ocm/data` (relative to the process working directory).

## Federation validator

`mode = "validator"` (sample: `configs/validator.toml`) mounts
`GET /validator/api/scan` as a public, anonymous endpoint. The shared
`scan_public` / `start_public` budget is 10 requests / 60 seconds.
Scan targets are SSRF-guarded: non-public literals and localhost are
rejected. There is no production `allow_private_targets` knob. The same
public, rate-limited, SSRF-guarded scan applies when
`[validator.active] enabled = false` (passive-only).

`[validator.active] enabled` turns on active-session legs. Unset means
enabled (the default). When false, active legs stay unbuilt; scan still
mounts and stays public and rate-limited.

Validator mode requires `outbound_http.ssrf.mode=strict`. Startup rejects
any other value. See [outbound-http-ssrf.md](outbound-http-ssrf.md).

## Example configs

| Path | Use |
| ---- | --- |
| `configs/validator.toml` | Federation validator preset sample (`mode = "validator"`) |
| `docker/configs/config.toml` | Minimal dev preset for containers (`mode = "dev"`) |
| `docker/configs/config-tls.toml` | Strict preset with static TLS cert paths |
| `tests/ca_pool/configs/valid.toml` | Valid outbound root CA path (manual runs) |
| `tests/ca_pool/configs/invalid.toml` | Invalid CA path (expect startup failure) |

Integration and unit tests build config in code or via
`internal/testsupport/ocm/configfixture/` rather than checking in large TOML
trees.

## Verification boundary

Strict verification exercises a narrow contract. A green strict run does not
prove broad peer interoperability.

Read [verification-boundary.md](verification-boundary.md) for:

- What strict SSRF and signature settings prove
- What remains operator-gated (containers and external suites)
- How route policies interact with strict verification

Directory Service and `/ocm-aux/*` helpers:
[directory-service-and-ocm-aux.md](directory-service-and-ocm-aux.md).

## Related docs

- [development.md](development.md) - run commands and local workflow
- [architecture.md](architecture.md) - how config flows into wiring
- [identity-and-public-origin.md](identity-and-public-origin.md) -
  `public_origin` and `external_base_path`
- [discovery.md](discovery.md) - discovery fields from config
- [testing.md](testing.md) - config fixtures in tests
