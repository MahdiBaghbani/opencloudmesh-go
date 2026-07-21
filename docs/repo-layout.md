# Repo layout

Directory map for opencloudmesh-go after the structural cleanup. Use this
doc to find production code, tests, configs, and documentation.

## Top level

```text
opencloudmesh-go/
  cmd/                  Binary entrypoints
  docker/               Dockerfile and sample TOML configs
  docs/                 Developer documentation (this tree)
  internal/             All library and test-support code
  scripts/              Build and helper scripts (e.g. build-docker.sh)
  tests/                Top-level integration, E2E, and CA pool tests
  Makefile              Build and test targets
  go.mod                Module: github.com/MahdiBaghbani/opencloudmesh-go
  README.md             Quickstart and navigation hub
```

## cmd/

```text
cmd/opencloudmesh-go/main.go   Server binary entrypoint
```

`main.go` loads config (preset -> TOML -> CLI flags), calls `wiring.Build`,
bootstraps admin identity, runs posture checks, and starts the HTTP server.

## internal/

### internal/architecture/

Architecture guard tests only. These files enforce import boundaries,
naming rules, spec pin integrity, and wire-DTO placement. They run as part
of `make test-go`. See [architecture.md](architecture.md).

### internal/wiring/

Composition root. `Build` wires persistence, outbound HTTP, signature
middleware, and returns `wiring.BuildResult`, which includes `Deps` plus
other built values (`RootCAPool`, `Persistence`).

### internal/frameworks/

```text
frameworks/service/   Service registry, descriptors, startup
```

### internal/platform/

Shared infrastructure with no OCM domain knowledge:

```text
platform/config/      Presets, TOML loading, validation
platform/http/        HTTP subpackages: client/, server/, middleware/, realip/, tls/
platform/cache/       Cache drivers (memory, redis) + loader
platform/store/       Persistence stores (json, sqlite)
platform/repos/       Repo adapters and lifecycle
platform/crypto/      Signing keys and key IDs
platform/appctx/      Request-scoped context helpers
platform/hostport/    Host/port parsing
platform/instanceid/  Instance ID helpers
platform/logutil/     Logging helpers
```

### internal/components/

Domain logic:

```text
components/ocm/           OCM protocol (discovery, shares, invites, token, ...)
components/api/           First-party REST API for UI and operators
components/identity/      Users, sessions, bootstrap admin
components/ocmaux/        Logic for /ocm-aux helper endpoints
components/ui/            UI templates and assets
components/webdav/        WebDAV access helpers
```

The OCM spec pin and vendored excerpt live under
`components/ocm/spec/vendor/`.

### internal/services/

HTTP route handlers (thin adapters over components):

```text
services/wellknown/   /.well-known/ocm
services/ocm/         /ocm/* provider endpoints
services/api/         /api/* first-party API
services/webdav/      WebDAV routes
services/ocmaux/      /ocm-aux/* helper endpoints
services/ui/          UI routes
```

### internal/interceptors/

HTTP middleware registered on the server. Root-level files handle
shared interceptor config and wiring; subdirectories implement
specific middleware:

```text
interceptors/ratelimit/   Rate limiting interceptor
```

### internal/testsupport/

Test-only helpers. **Not for production imports.** Guarded by
`internal/architecture/testsupport_imports_test.go`.

```text
testsupport/callscan/   Call-site scanning helpers
testsupport/cfg/        Config fixtures and patches
testsupport/http/       HTTP test clients and assertions
testsupport/log/        Log capture for tests
testsupport/modroot/    Module root resolution for arch tests
testsupport/ocm/        OCM-specific fixtures (config TOML, helpers)
testsupport/repos/      Test persistence backends
testsupport/store/      Store bootstrap and contract helpers
testsupport/wiring/     Wiring fixtures for unit tests
```

Unit tests under `internal/` import these packages from `_test.go` files.
Integration tests may also use them where appropriate.

## tests/

Top-level test trees. Raw `go test ./...` includes `tests/integration/` and
`tests/ca_pool/`; only `tests/e2e/` is outside Go's `./...` (Playwright/Bun,
not Go):

```text
tests/integration/    In-process and subprocess integration tests
  harness/              Shared server startup for integration tests
tests/e2e/              Playwright browser tests (Bun + TypeScript)
tests/ca_pool/          Outbound TLS root CA pool tests
```

| Tree | README | Make target |
| ---- | ------ | ----------- |
| `tests/integration` | [tests/integration/README.md](../tests/integration/README.md) | `make test-integration` |
| `tests/e2e` | [tests/e2e/README.md](../tests/e2e/README.md) | `make test-e2e` |
| `tests/ca_pool` | [tests/ca_pool/README.md](../tests/ca_pool/README.md) | `make test-go` (focused: `go test ./tests/ca_pool/...`) |

## docs/

Permanent developer documentation:

```text
docs/architecture.md
docs/repo-layout.md              (this file)
docs/testing.md
docs/development.md
docs/configuration.md
docs/identity-and-public-origin.md
docs/routes-and-auth.md
docs/protocol-endpoints.md
docs/discovery.md
docs/invite-wayf-and-accept.md
docs/directory-service-and-ocm-aux.md
docs/outbound-http-ssrf.md
docs/naming-conventions.md
docs/verification-boundary.md
```

## docker/

```text
docker/Dockerfile
docker/configs/config.toml       Minimal dev config for containers
docker/configs/config-tls.toml   Strict preset with static TLS paths
```

## Where to add new code

| Change | Location |
| ------ | -------- |
| New OCM protocol behavior | `internal/components/ocm/<area>/` |
| New HTTP route | `internal/services/<group>/` + registry descriptor |
| New config field | `internal/platform/config/` |
| New persistence backend | `internal/platform/store/` + `internal/platform/repos/` |
| New unit test helper | `internal/testsupport/<area>/` (test-only) |
| New architecture rule | `internal/architecture/<topic>_test.go` |
| New integration scenario | `tests/integration/<name>_test.go` |
| New browser scenario | `tests/e2e/specs/<name>.spec.ts` |
