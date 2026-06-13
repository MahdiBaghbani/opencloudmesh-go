# opencloudmesh-go

Open Cloud Mesh (OCM) server implementation in Go. The runtime targets a
practical WebDAV-centered subset of the pinned OCM-API surface: discovery,
`shareType=user`, the current notification subset, and strict token-exchange
and HTTP-signature behavior on that reduced path.

## Quickstart

From the repo root:

```sh
# Build the server binary
make build

# Run unit and integration tests (excludes E2E)
make test

# Run E2E tests (install browsers once, then run)
make test-e2e-install
make test-e2e
```

Run the server locally:

```sh
# Strict preset (default when no config or -mode is given)
./bin/opencloudmesh-go

# Dev preset via CLI
./bin/opencloudmesh-go -mode dev

# Strict preset with a TOML file
./bin/opencloudmesh-go -config docker/configs/config-tls.toml

# Override preset from the CLI (precedence: preset -> TOML -> flags)
./bin/opencloudmesh-go -mode strict -public-origin https://localhost:9200
```

Docker build and run notes remain in the Docker section below.

## Documentation

| Topic | Doc |
| ----- | --- |
| Architecture and layering | [docs/architecture.md](docs/architecture.md) |
| Repo layout (code and tests) | [docs/repo-layout.md](docs/repo-layout.md) |
| Testing (unit, integration, E2E) | [docs/testing.md](docs/testing.md) |
| Development workflow | [docs/development.md](docs/development.md) |
| Configuration and presets | [docs/configuration.md](docs/configuration.md) |
| Naming conventions | [docs/naming-conventions.md](docs/naming-conventions.md) |
| Strict verification boundary | [docs/verification-boundary.md](docs/verification-boundary.md) |
| Directory Service vs /ocm-aux | [docs/directory-service-vs-ocmaux-federations.md](docs/directory-service-vs-ocmaux-federations.md) |

Test-specific guides:

- [tests/integration/README.md](tests/integration/README.md) - in-process
  integration harness
- [tests/e2e/README.md](tests/e2e/README.md) - Playwright browser tests
- [tests/ca_pool/README.md](tests/ca_pool/README.md) - outbound TLS root CA
  pool tests

## Repo navigation

```text
cmd/opencloudmesh-go/     Binary entrypoint
internal/                 Production and test-support code
  architecture/           Architecture guard tests
  components/             Domain logic (ocm, api, identity, ...)
  frameworks/             Service registry and startup
  interceptors/           HTTP middleware (ratelimit, ...)
  platform/               Config, HTTP, cache, store, repos
  services/               HTTP route handlers
  testsupport/            Test-only helpers (not for production)
  wiring/                 Composition root (Build)
tests/                    Top-level integration, E2E, and CA pool tests
docs/                     Developer documentation
docker/                   Container image and sample configs
```

See [docs/repo-layout.md](docs/repo-layout.md) for the full map.

## Presets and configuration

The server resolves config in this order: preset bundle, TOML file, CLI flags.

Preset bundles: `strict`, `compat`, and `dev`. They are convenience entry
points, not the sole authority for runtime posture. Effective behavior also
depends on `compatibility_scope` and the signature, transport, trust, and
peer-compat axes.

Example configs:

- `docker/configs/config.toml` - minimal dev preset for containers
- `docker/configs/config-tls.toml` - strict preset with static TLS
- `tests/ca_pool/configs/valid.toml` - valid outbound root CA path
- `tests/ca_pool/configs/invalid.toml` - invalid CA path (startup failure)

Details: [docs/configuration.md](docs/configuration.md).

## Build and test

```sh
make build              # go build -> bin/opencloudmesh-go
make test-go            # unit tests (excludes tests/integration)
make test-integration   # integration tests only
make test               # test-go + test-integration
make test-e2e-install   # bun install + Playwright browsers
make test-e2e           # Playwright E2E (builds binary first)
make fmt vet tidy       # formatting and static checks
```

See [docs/testing.md](docs/testing.md) and [docs/development.md](docs/development.md).

## Docker

Build and run the server in a container.

| Mode  | Port | Description |
| ----- | ---- | ----------- |
| HTTP  | 8080 | Default. No TLS. |
| TLS   | 443  | Set TLS_ENABLED=true. Uses pre-installed or env-provided certs. |

| Pre-installed files    | Purpose |
| ---------------------- | ------- |
| ocm-go.crt, ocm-go.key | Leaf cert and key |
| dockypody.crt          | CA for trust store |

Pre-installed cert hostnames: ocm-go.docker, ocm-go1.docker through
ocm-go4.docker, localhost, 127.0.0.1, ::1

```sh
# Build
./scripts/build-docker.sh
# or: docker build -t opencloudmesh-go:local -f docker/Dockerfile .

# HTTP mode (default)
docker run -d -p 8080:8080 -e HOST=ocm-go1 opencloudmesh-go:local
curl http://localhost:8080/.well-known/ocm

# TLS mode (pre-installed certs)
docker run -d -p 443:443 -e HOST=ocm-go1 -e TLS_ENABLED=true opencloudmesh-go:local
curl -k https://localhost/.well-known/ocm

# Custom config (mount your config and set CONFIG path)
docker run -d -p 8080:8080 -v /path/to/config.toml:/config/config.toml:ro \
  -e CONFIG=/config/config.toml -e HOST=ocm-go1 opencloudmesh-go:local
```

### Environment variables

**Identity (set at least one of HOST or PUBLIC_ORIGIN):**

| Variable      | Required               | Description |
| ------------- | ---------------------- | ----------- |
| HOST          | If PUBLIC_ORIGIN empty | Short hostname (e.g. ocm-go1). Added to /etc/hosts. Used to derive PUBLIC_ORIGIN. |
| PUBLIC_ORIGIN | If HOST empty          | Full base URL. Passed as --public-origin. |

**Mode:**

| Variable    | Default | Description |
| ----------- | ------- | ----------- |
| OCM_GO_MODE | (none)  | Override preset bundle: `strict`, `compat`, or `dev`. |

**Config:**

| Variable | Default | Description |
| -------- | ------- | ----------- |
| CONFIG   | (auto)  | Path to config.toml in container. Use with `-v` to mount your own file. |

**TLS:**

| Variable    | Default | Description |
| ----------- | ------- | ----------- |
| TLS_ENABLED | false   | Set to `true` for TLS on port 443. |
| TLS_CERT    | (none)  | Base64-encoded PEM cert. Overwrites pre-installed cert at startup. |
| TLS_KEY     | (none)  | Base64-encoded PEM key. Overwrites pre-installed key at startup. |
| TLS_CA      | (none)  | Base64-encoded PEM CA. Overwrites pre-installed CA and updates trust store. |

## OCM-API specification

Protocol behavior is defined in the [OCM-API IETF-RFC][ocm-rfc]. The vendored
pin lives at `internal/components/ocm/spec/vendor/pin.json`.

[ocm-rfc]: https://github.com/cs3org/OCM-API/blob/a2b8bacd4590ff201a06883330b67636e99c4f5b/IETF-RFC.md?plain=1#ocm-api-discovery
