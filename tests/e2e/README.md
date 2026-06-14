# E2E tests

Browser end-to-end tests using Playwright and Bun.

## Location

```text
tests/e2e/
  specs/               Playwright test files (*.spec.ts)
  harness/             Subprocess server startup (server.ts)
  testdata/tls/        Localhost TLS cert for test servers
  playwright.config.ts Playwright configuration
  package.json         Bun scripts and devDependencies
```

## Prerequisites

From the repo root:

```sh
make test-e2e-install
```

This runs `bun install` and `bun run install:browsers` (Chromium).

## Run

```sh
make test-e2e
```

`make test-e2e` builds `bin/opencloudmesh-go` first, then runs Playwright.

Manual runs from `tests/e2e/`:

```sh
bun run test              # headless
bun run test:headed       # visible browser
bun run test:debug        # Playwright inspector
```

## How tests start servers

`harness/server.ts` spawns the Go binary as a subprocess with:

- Dynamic port on `127.0.0.1`
- Temp data directory per instance
- Static TLS using `testdata/tls/` and the DockyPody CA from
  `tests/ca_pool/testdata/certificate-authority/`
- Optional `mode` (`dev`, `compat`, `strict`) and extra TOML snippets

Playwright config sets `workers: 1` and `fullyParallel: false` so subprocess
servers do not collide on ports.

HTTPS errors are ignored in tests because servers use project-local TLS
material, not public CA chains.

## Spec overview

| Spec | Focus |
| ---- | ----- |
| `smoke.spec.ts` | Basic availability |
| `login.spec.ts` | UI login |
| `inbox.spec.ts`, `inbox-ui.spec.ts` | Inbox flows |
| `invites.spec.ts`, `outgoing-invites.spec.ts` | Invite flows |
| `invite-flow.spec.ts`, `accept-share.spec.ts` | Share acceptance |
| `wayf.spec.ts`, `wayf-two-instance.spec.ts` | WAYF UI (Alice discovers Bob, accept flow) |
| `two-instance-share-with.spec.ts` | Two-instance sharing |

WAYF browser proofs complement integration tests in
`wayf_invite_accept_test.go` and `accept_invite_redirect_test.go`.
Guide: [docs/invite-wayf-and-accept.md](../../docs/invite-wayf-and-accept.md).

## Artifacts

Failed runs may leave traces, screenshots, and videos under
`tests/e2e/test-results/`. `make clean` removes `test-results` and
`node_modules`.

## Related docs

- [docs/testing.md](../../docs/testing.md) - E2E vs unit/integration
- [docs/development.md](../../docs/development.md) - local dev workflow
- [tests/ca_pool/README.md](../ca_pool/README.md) - CA fixture shared with E2E
