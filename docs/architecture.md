# Architecture

This document describes how the opencloudmesh-go server is structured, how
packages depend on each other, and where architectural rules are enforced.

## Overview

The server is a Go HTTP application that implements a WebDAV-centered OCM
subset. Startup follows a fixed sequence:

1. Load and validate configuration (`internal/platform/config`).
2. Wire shared infrastructure (`internal/wiring.Build`).
3. Register and start HTTP services (`internal/frameworks/service`,
   `internal/platform/http/server`).

The binary entrypoint is `cmd/opencloudmesh-go/main.go`. It owns config
loading, logger setup, admin bootstrapping, posture checks, and server
lifecycle. `internal/wiring` is the composition root: it builds persistence,
shared clients, and the dependency graph passed to route handlers.

## Layering

Code is organized into layers with import boundaries enforced by tests in
`internal/architecture`:

| Layer | Path | Role |
| ----- | ---- | ---- |
| Entry | `cmd/` | Process startup and CLI |
| Composition | `internal/wiring` | Wire deps from config |
| HTTP surface | `internal/services` | Route handlers and HTTP adapters |
| Middleware | `internal/interceptors` | Cross-cutting HTTP concerns |
| Domain | `internal/components` | OCM protocol logic, API helpers, UI |
| Platform | `internal/platform` | Config, HTTP client/server, cache, store |
| Framework | `internal/frameworks` | Service registry and descriptors |

Key rules (see `internal/architecture/layering_test.go`):

- `internal/components/ocm` must not import `internal/components/api`.
  Dependency flows api -> ocm, not the reverse.
- `internal/services` and `internal/interceptors` must not import
  `internal/platform/deps` or `internal/wiring` directly.
- Production code must not use blank imports of `services/loader` or
  `interceptors/loader`. Registration is explicit via the service registry.

## Components vs services

**Components** (`internal/components/`) hold domain logic:

- `ocm/` - protocol implementations (discovery, shares, invites, token
  exchange, directory service client, and peer trust)
- `api/` - first-party REST helpers for the bundled UI and operators
- `identity/` - users, sessions, and bootstrap admin
- `ocmaux/` - helper logic backing `/ocm-aux/*` UX endpoints
- `ui/` - server-rendered UI assets
- `webdav/` - WebDAV file access helpers

**Services** (`internal/services/`) are thin HTTP handlers that adapt
requests to component APIs. Each service package maps to a route group
(for example `wellknown`, `ocm`, `api`, `webdav`, `ocmaux`, `ui`).

## Wiring and persistence

`wiring.Build(cfg, logger, opts)` creates persistence repos, outbound HTTP
clients, signature middleware, and returns `wiring.BuildResult`. Callers
use `BuildResult` fields: `Deps` (dependency graph for route handlers),
`RootCAPool` and `Persistence`. Callers pass an
already-loaded `*config.Config`.

Persistence backends are selected from config and constructed in
`internal/platform/repos`. Store implementations live under
`internal/platform/store/` (JSON and SQLite drivers).

## Service registry

`internal/frameworks/service` defines service descriptors and startup
ordering. Handlers register through the registry rather than ad-hoc route
tables scattered across the tree.

## Spec pin

OCM protocol behavior is pinned to a vendored spec snapshot:

- `internal/components/ocm/spec/vendor/pin.json` - commit and version pin
- `internal/components/ocm/spec/vendor/spec.yaml` - vendored spec excerpt

`internal/architecture/spec_pin_test.go` asserts the pin is present and
matches the expected commit.

## Signing direction

The OCM-API [Signing Direction Index][signing-direction-index] is the
authoritative signer/verifier map for protocol HTTP Message Signatures.
The index is INFORMATIVE. HTTP Message Signatures apply only when the
peer advertises `http-sig`; `must-use-http-sig` makes signing mandatory
for inbound requests. See the [applicability rules][signing-applicability].

[signing-direction-index]: https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L882-L912
[signing-applicability]: https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L796-L812

| Flow | Endpoint | Signer | Verifier |
| ---- | -------- | ------ | -------- |
| Share Creation Notification | POST /shares | Sending Server | Receiving Server |
| Token Request | POST {tokenEndPoint} | Receiving Server | Sending Server |
| Invite Acceptance | POST /invite-accepted | Invite Receiver | Invite Sender |
| Request for a Share | POST /request-share | Requesting Server | Requested Server |
| Share Acceptance Notification | POST /notifications | Receiving Server | Sending Server |
| Sender-initiated Notification | POST /notifications | Sending Server SHOULD sign | Receiving Server |

ocmgo signs outbound requests conditionally when the peer advertises
`http-sig`, and fails closed when no signer is available while the peer
advertises `http-sig`. Inbound verification runs through the signature
middleware (internal/components/ocm/inbound/signature/middleware.go), wired
per route in internal/services/ocm/mount.go: it verifies any present OCM
signature and rejects unsigned requests when `must-use-http-sig` applies.
Outbound signing lives in `internal/components/ocm/outbound/poster.go` and
`internal/components/ocm/token/outgoing/client.go`. Protocol endpoint
handlers (shares, invites, token) sit behind that middleware.

## Architecture guard tests

`internal/architecture/` contains test-only guard files. They are not
imported by production code. Run them with the normal unit test suite:

```sh
go test ./internal/architecture/...
```

Guard categories:

| Test file | What it enforces |
| --------- | ---------------- |
| `layering_test.go` | Package import boundaries between layers |
| `testsupport_imports_test.go` | `internal/testsupport` only in `_test.go` |
| `naming_conventions_test.go` | Banned DS abbreviations, spec Directory Service JSON tags, and address parsing |
| `production_loader_imports_test.go` | No loader blank imports in production |
| `spec_pin_test.go` | Vendored OCM spec pin integrity |
| `wire_dto_location_test.go` | Wire DTO placement rules |
| `internal/architecture` scheme guard | Peer-origin scheme boundary |
| `static_construction_test.go` | Static construction constraints |
| `forwarded_header_test.go` | Forwarded-header handling rules |
| `slog_keys_test.go` | Structured log key conventions |

## Test support boundary

`internal/testsupport/` provides helpers shared by unit and integration
tests. Architecture tests require that only `_test.go` files outside the
testsupport tree may import it. See [testing.md](testing.md) and
[repo-layout.md](repo-layout.md).

## Route policy guards

`internal/architecture/route_policy_wiring_test.go` enforces that
`service.Routes(opts)` and its projections (`DerivedAuthRows`,
`DerivedRouteGroups`, `DerivedRouteInventory`,
`SessionAuthRequiredForPath`) stay consistent. It also checks surface-class
rules: HTTP signature handler auth only on protocol routes, invite accept
dialog metadata on UI routes only, and peer trust classes on protocol routes.

Details: [routes-and-auth.md](routes-and-auth.md).

## Related docs

- [repo-layout.md](repo-layout.md) - directory map
- [testing.md](testing.md) - test layers and architecture guard details
- [routes-and-auth.md](routes-and-auth.md) - route specs and auth surfaces
- [identity-and-public-origin.md](identity-and-public-origin.md) - public
  identity derivation
- [naming-conventions.md](naming-conventions.md) - naming rules enforced
  by architecture tests
- [configuration.md](configuration.md) - presets and config axes
- [verification-boundary.md](verification-boundary.md) - what strict
  verification proves and does not prove
- [directory-service-and-ocm-aux.md](directory-service-and-ocm-aux.md) -
  Directory Service spec vs local `/ocm-aux/*` helpers
