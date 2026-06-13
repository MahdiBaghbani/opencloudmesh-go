# Configuration

How the server loads configuration, what presets mean, and where to find
example TOML files.

## Loading order

Effective configuration is resolved in this order (later wins):

1. **Preset bundle** - selected by `mode` (`strict`, `compat`, or `dev`)
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
| `-mode` | Preset bundle (`strict`, `compat`, or `dev`) |
| `-listen` | Listen address |
| `-public-origin` | Public origin URL |
| `-external-base-path` | External base path prefix |
| `-compatibility-scope` | `none`, `scoped`, or `unbounded` |
| `-signature-inbound-mode` | `strict`, `lenient`, or `off` |
| `-signature-outbound-mode` | `strict`, `criteria-only`, `token-only`, or `off` |
| `-signature-peer-profile-level-override` | `all`, `non-strict`, or `off` |
| `-peer-policy` | `legacy`, `prefer-strict`, or `strict` |
| `-token-exchange-enabled` | Enable token exchange |
| `-token-exchange-path` | Token exchange path under `/ocm/` |
| `-require-token-exchange` | Require must-exchange-token on receive |
| `-logging-level` | `trace`, `debug`, `info`, `warn`, `error` |
| `-logging-allow-sensitive` | Allow sensitive values in logs |
| `-admin-username` / `-admin-password` | Bootstrap admin credentials |

Implementation: `internal/platform/config/loader.go` and `presets.go`.

## Preset bundles

Presets are convenience entry points, not the sole authority for runtime
posture. Effective behavior also depends on `compatibility_scope` and the
signature, transport, trust, and peer-compat axes.

| Mode | Intent |
| ---- | ------ |
| `strict` | Production-safe defaults; `compatibility_scope=none` baseline |
| `compat` | Relaxed defaults for interoperability testing |
| `dev` | Local development; more permissive transport and logging |

When `compatibility_scope=none`, the server exits at startup if the resolved
runtime posture is not strict. That guard lives in `main.go` after
`wiring.Build`.

## Major config sections

TOML sections map to `internal/platform/config.Config`:

| Section | Role |
| ------- | ---- |
| `mode` | Preset bundle selector |
| `compatibility_scope` | Exception-governance axis |
| `public_origin`, `listen_addr`, `external_base_path` | Identity and binding |
| `[server]` | Trusted proxies |
| `[tls]` | TLS mode (selfsigned, static, acme, ...) |
| `[outbound_http]` | Outbound client, SSRF, proxy, TLS roots |
| `[signature]` | HTTP signature inbound/outbound modes |
| `[peer_profiles]` | Peer compatibility mappings |
| `[peer_trust]` | Federation membership trust |
| `[token_exchange]` | Token exchange endpoint settings |
| `[logging]` | Log level and sensitivity |
| `[cache]` | Cache driver selection |
| `[persistence]` | Store backend (memory, json, sqlite, mirror) |
| `[http]` | Per-service HTTP limits |

## Example configs

| Path | Use |
| ---- | --- |
| `docker/configs/config.toml` | Minimal dev preset for containers (`mode = "dev"`) |
| `docker/configs/config-tls.toml` | Strict preset with static TLS cert paths |
| `tests/ca_pool/configs/valid.toml` | Valid outbound root CA path (manual runs) |
| `tests/ca_pool/configs/invalid.toml` | Invalid CA path (expect startup failure) |

Integration and unit tests build config in code or via
`internal/testsupport/ocm/configfixture/` rather than checking in large TOML
trees.

## Verification boundary

Strict verification exercises a narrow contract on the `compatibility_scope=none`
lane. A green strict run does not prove broad peer interoperability.

Read [verification-boundary.md](verification-boundary.md) for:

- What strict SSRF and signature settings prove
- What remains operator-gated (peer profiles, containers, external suites)
- How route policies interact with compatibility scope

Directory Service spec behavior vs local `/ocm-aux/*` helpers:
[directory-service-vs-ocmaux-federations.md](directory-service-vs-ocmaux-federations.md).

## Related docs

- [development.md](development.md) - run commands and local workflow
- [architecture.md](architecture.md) - how config flows into wiring
- [testing.md](testing.md) - config fixtures in tests
