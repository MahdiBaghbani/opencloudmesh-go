# Integration tests

In-process and subprocess integration tests for opencloudmesh-go.

## Location

```text
tests/integration/
  harness/              Shared server startup utilities
  *_test.go             Integration scenarios
```

Run from the repo root:

```sh
make test-integration
# or: go test -race ./tests/integration/...
```

## Harness

Package `tests/integration/harness` starts a real server for tests:

- `StartTestServer` - dev defaults, dynamic port, temp data dir
- `StartTestServerWithConfig` - optional `patch func(*config.Config)` before
  startup
- Subprocess helpers in `harness/subprocess.go` for scenarios that need an
  isolated process or custom transport

The harness mirrors production startup: load config, `wiring.Build`, register
services, listen on an ephemeral port. Tests receive a `TestServer` with
`Server`, `BaseURL`, `Config`, `Deps`, and `TempDir`.

Wire options for tests that need custom wiring patches:
`harness/wire_options.go`.

## What integration tests cover

Examples in this tree:

- Health and two-instance discovery
- Token exchange flows, policy, and error paths
- OCM identity and federation listing
- Runtime posture and ratelimit behavior
- ACME and subprocess transport scenarios

These tests exercise multiple layers together. Prefer unit tests under
`internal/` for single-package logic.

## internal/testsupport

Integration tests may import `internal/testsupport` helpers (for example
config fixtures from `testsupport/ocm/`). Production code must not import
testsupport; see `internal/architecture/testsupport_imports_test.go`.

## Related docs

- [docs/testing.md](../../docs/testing.md) - full test layer overview
- [docs/repo-layout.md](../../docs/repo-layout.md) - repo map
- [docs/verification-boundary.md](../../docs/verification-boundary.md) -
  strict contract scope
