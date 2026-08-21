<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.
-->

# Testing

How unit, integration, E2E, and CA pool tests are organized and run in
opencloudmesh-go.

## Test policy

This is the project's formal written test policy.

- **Tests are mandatory for new functionality.** Any change that adds
  non-trivial new behavior to the software MUST add automated tests for that
  behavior to the same pull request. A pull request that adds functionality
  without tests is blocked, not deferred.
- **Bug fixes add regression tests.** A fix for a reproducible bug MUST add a
  regression test that fails before the fix and passes after it.
- **Where tests live.** Unit tests live next to the code they cover under
  `internal/**/*_test.go`. Integration tests live under
  `tests/integration/`. E2E tests live under `tests/e2e/`. Shared test
  helpers live under `internal/testsupport/` and must not be imported by
  production code (enforced by architecture guard tests).
- **What must pass.** The `ci` rollup gate requires unit and integration
  tests to pass on every pull request. E2E and fuzz run as separate surfaces
  so a slow layer never blocks the others.
- **Coverage must not regress.** Statement coverage is tracked and enforced:
  the unit suite must stay at or above 80% statement coverage, checked by
  `make coverage-check` (run in CI after `make test-go`). A pull request that
  drops unit coverage below 80% is blocked. See the Coverage policy section
  below for how the floor is measured.

The behavior verification map below cites the packages and tests that prove
each behavior. When you change invite, discovery, or route-policy code, add
or update the corresponding entry.

### Coverage policy

The project enforces a minimum statement-coverage floor on its automated
test suites:

- `make test-go` writes `coverage-unit.out` with
  `-coverpkg=./internal/...,./cmd/...`.
- `make coverage-check` reads that profile, prints the unit statement
  coverage percentage, and fails if it is below `COVERAGE_THRESHOLD`
  (default 80).
- CI runs `make coverage-check` after the unit tests, so a pull request that
  drops unit coverage below 80% fails the `ci` rollup.

The unit suite alone currently exceeds 80%; the integration suite
(`coverage-integration.out`) adds further coverage on top. The live number is
reported by `make coverage-check` and by the Coveralls badge in the README, so
this doc does not hard-code a percentage that would drift.

## Test layers

| Layer | Location | Command | What it exercises |
| ----- | -------- | ------- | ----------------- |
| Unit | `internal/**/*_test.go` | `make test-go` | Packages in isolation |
| Architecture guards | `internal/architecture/` | `make test-go` | Import boundaries, naming, spec pin |
| Integration | `tests/integration/` | `make test-integration` | Full server in-process or subprocess |
| CA pool | `tests/ca_pool/` | `make test-go` | Outbound TLS root CA file loading |
| E2E | `tests/e2e/` | `make test-e2e` | Browser flows via Playwright |

`make test` runs unit tests plus integration tests. E2E is separate because it
needs Bun, Playwright browsers, and a built binary.

## Unit tests

Unit tests live next to the code they cover under `internal/`. Run them with:

```sh
make test-go
# or: go test -race $(go list ./... | grep -v /tests/integration)
```

`make test-go` intentionally excludes `tests/integration` from the `go list
./...` sweep with `grep -v /tests/integration`, then runs that tree
separately via `make test-integration`. That is a Makefile policy split, not
a separate Go module.

### Architecture guard tests

`internal/architecture/` is a dedicated package of guard tests. They are not
imported by production code. See [architecture.md](architecture.md) for the
full list of enforced rules.

```sh
go test ./internal/architecture/...
```

### internal/testsupport

`internal/testsupport/` holds helpers shared by unit and integration tests.
Production `.go` files must not import it. The guard
`internal/architecture/testsupport_imports_test.go` enforces that only
`_test.go` files (outside the testsupport tree) may import testsupport
packages.

Subpackages:

| Package | Role |
| ------- | ---- |
| `callscan/` | Scan call sites in tests |
| `cfg/` | Config fixture builders |
| `http/` | HTTP client helpers for tests |
| `log/` | Log capture |
| `modroot/` | Resolve module root for arch walks |
| `ocm/` | OCM config TOML fixtures |
| `repos/` | Test persistence backends |
| `store/` | Store bootstrap and contracts |
| `wiring/` | Wiring fixtures for unit tests |

Add new shared test helpers here rather than duplicating setup in every
`_test.go` file.

## Integration tests

Integration tests live in `tests/integration/`. They use the in-process
harness at `tests/integration/harness/` to start a real server on a dynamic
port with a temp data directory.

Guide: [tests/integration/README.md](../tests/integration/README.md)

```sh
make test-integration
# or: go test -race ./tests/integration/...
```

Some scenarios spawn subprocess servers (see `subprocess_transport_test.go`
and related files). The harness supports both in-process and subprocess modes.

## CA pool tests

`tests/ca_pool/` validates outbound TLS root CA file loading. These tests
are included in `make test-go` and therefore in `make test`. Run the
focused command when touching outbound HTTP TLS configuration:

Guide: [tests/ca_pool/README.md](../tests/ca_pool/README.md)

```sh
go test -v ./tests/ca_pool/...
```

## E2E tests

Browser tests use Playwright and Bun under `tests/e2e/`. They start
subprocess server instances via `tests/e2e/harness/server.ts`.

Guide: [tests/e2e/README.md](../tests/e2e/README.md)

```sh
make test-e2e-install   # once: bun install + chromium
make test-e2e           # builds binary, then runs Playwright
```

E2E runs sequentially (`workers: 1`) to avoid port conflicts between
subprocess servers.

## CI wiring

The test layers are wired into GitHub Actions as three separate surfaces, so a
slow or skipped layer never blocks the others.

| Surface | Workflow | When it runs | Required check |
| ------- | -------- | ------------ | -------------- |
| Unit + integration | `ci-test.yml` calls `ci-test-unit-integration.yml` | push (master), pull request, workflow_dispatch, daily schedule (via the `ci.yml` rollup `test` job) | `ci` rollup |
| E2E | `ci-test-e2e.yml` | push (master), pull request, workflow_dispatch, daily schedule; path-filtered on push/pull_request (skipped when the diff touches no e2e-relevant paths), always runs on schedule or manual dispatch | `e2e-result` |
| Fuzz | `ci-test-fuzz.yml` | weekly schedule (Monday 09:00 UTC), workflow_dispatch, and pull requests; runs unconditionally on schedule or manual dispatch, on pull requests skipped unless the diff touches fuzz-relevant paths | standalone, optionally required |

The `ci.yml` rollup gates lint, security, licenses, test (unit plus
integration), build, pins, and reuse behind a single `ci` required check.
E2E is not part of the rollup: it runs as its own workflow and surfaces through
the `e2e-result` job, which reports success when the e2e job passes, or when it
is correctly skipped by the path filter on push/pull_request events (scheduled
and manual runs always run). Fuzz is also standalone (not in the rollup); it
is optionally required, and becomes a hard required check once added to branch
protection.

## Behavior verification map

Focused docs cite the packages and tests that prove each behavior. Use this
map to find the right proof when changing invite, discovery, or route
policy code.

| Behavior | Doc | Verification command |
| -------- | --- | -------------------- |
| Public identity, default-port strip, base path | [identity-and-public-origin.md](identity-and-public-origin.md) | `go test ./internal/platform/localidentity/...` |
| Route specs, `Routes(opts)`, projections | [routes-and-auth.md](routes-and-auth.md) | `go test ./internal/architecture/... -run RoutePolicy` |
| Discovery fields and config | [discovery.md](discovery.md) | `go test ./internal/services/wellknown/... -run 'DiscoveryFields\|InviteAcceptDialogFromRoutes\|InviteWAYFCapability\|TruthfulCapabilitySet'` |
| Protocol vs UI vs helper surfaces | [protocol-endpoints.md](protocol-endpoints.md), [routes-and-auth.md](routes-and-auth.md) | `go test ./internal/frameworks/service/... -run Route` |
| WAYF Alice/Bob, accept-invite redirect | [invite-wayf-and-accept.md](invite-wayf-and-accept.md) | `go test ./tests/integration/... -run 'Wayf\|AcceptInvite'` |
| MVP invite API (no WAYF) | [invite-wayf-and-accept.md](invite-wayf-and-accept.md) | `go test ./tests/integration/... -run TestInviteAcceptTwoInstanceAPI` |
| Discover normalization | [invite-wayf-and-accept.md](invite-wayf-and-accept.md) | `go test ./tests/integration/... -run TestOCMAuxDiscover` |
| Directory Service JWS | [directory-service-and-ocm-aux.md](directory-service-and-ocm-aux.md) | `go test ./tests/integration/... -run TestDirectoryServiceJWSFeedsFederations` |
| SSRF on discover | [outbound-http-ssrf.md](outbound-http-ssrf.md) | `go test ./tests/integration/... -run TestOCMAuxDiscover_SSRF` |
| WAYF browser flows | [invite-wayf-and-accept.md](invite-wayf-and-accept.md) | `make test-e2e` (specs `wayf.spec.ts`, `wayf-two-instance.spec.ts`) |
| Live discovery from server | [discovery.md](discovery.md) | `go test ./tests/integration/... -run 'DiscoveryEndpoint\|DiscoveryRemains\|DiscoveryRoutesMatch'` |

## Verification boundary

Strict verification proves a narrow contract. A green strict run does not
claim broad peer interoperability. See
[verification-boundary.md](verification-boundary.md).

## Related docs

- [repo-layout.md](repo-layout.md) - where tests live in the tree
- [development.md](development.md) - fmt, vet, and local workflow
- [architecture.md](architecture.md) - architecture guards
