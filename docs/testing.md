# Testing

How unit, integration, E2E, and CA pool tests are organized and run in
opencloudmesh-go.

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
