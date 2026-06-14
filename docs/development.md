# Development

Local workflow for building, testing, and changing opencloudmesh-go.

## Prerequisites

- Go (module path: `github.com/MahdiBaghbani/opencloudmesh-go`)
- For E2E: [Bun](https://bun.sh) and Playwright browsers
  (`make test-e2e-install`)

## Build

```sh
make build
# -> bin/opencloudmesh-go
```

Run locally:

```sh
./bin/opencloudmesh-go                    # strict preset (default)
./bin/opencloudmesh-go -mode dev          # dev preset via CLI
./bin/opencloudmesh-go -config docker/configs/config-tls.toml
```

Config precedence: preset bundle -> TOML file -> CLI flags. See
[configuration.md](configuration.md).

## Test during development

```sh
make fmt                # go fmt ./...
make vet                # go vet ./...
make tidy               # go mod tidy
make test-go            # all Go packages except tests/integration
make test-integration   # integration harness
make test               # test-go + test-integration
```

Run a single package:

```sh
go test -race ./internal/components/ocm/discovery/...
go test -race ./tests/integration/... -run TestHealth
```

E2E (after `make test-e2e-install`):

```sh
cd tests/e2e && bun run test:headed   # visible browser
cd tests/e2e && bun run test:debug    # Playwright inspector
```

Details: [testing.md](testing.md).

## Where to change things

| Task | Start here |
| ---- | ---------- |
| New HTTP route | `internal/services/<group>/`, service registry ([routes-and-auth.md](routes-and-auth.md)) |
| OCM protocol logic | `internal/components/ocm/<area>/` ([protocol-endpoints.md](protocol-endpoints.md)) |
| Config field | `internal/platform/config/` ([configuration.md](configuration.md)) |
| Wire new dependency | `internal/wiring/` |
| Architecture rule | `internal/architecture/<topic>_test.go` |
| Shared test helper | `internal/testsupport/<area>/` |
| Integration scenario | `tests/integration/<name>_test.go` |
| Browser scenario | `tests/e2e/specs/<name>.spec.ts` |

Full tree map: [repo-layout.md](repo-layout.md).

## Docker

Container build and run notes are in the README Docker section. Image build
uses `scripts/build-docker.sh` or `docker build -f docker/Dockerfile`.

Sample configs:

- `docker/configs/config.toml` - minimal dev preset
- `docker/configs/config-tls.toml` - strict preset with static TLS paths

## Naming and style

Follow [naming-conventions.md](naming-conventions.md). Architecture tests
enforce several naming and import rules automatically.

## Related docs

- [configuration.md](configuration.md) - presets and config axes
- [architecture.md](architecture.md) - layering and guards
- [routes-and-auth.md](routes-and-auth.md) - route specs and surfaces
- [invite-wayf-and-accept.md](invite-wayf-and-accept.md) - WAYF dev flows
- [verification-boundary.md](verification-boundary.md) - strict contract scope
