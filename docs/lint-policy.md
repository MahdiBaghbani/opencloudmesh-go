<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.
-->

# Lint policy

Durable record of the golangci-lint bar for opencloudmesh-go and the
small set of retained, justified `//nolint` directives. Configuration lives
in `.golangci.yml`; this document explains how we apply it.

## One standard

Production and test code share the same lint standard. Tests are not a
second-class surface: the same linters run with the same severity rules.
There is no test-path waiver, cyclop complexity budget, or other YAML
exclusion that relaxes the bar for `_test.go` files or test directories.

## Refactor-first suppressions

Every `//nolint` directive is a burn-down candidate. Preferred fix is always
to change the code so the linter passes. Laziness and excuse suppressions
("too noisy", "will fix later", "test only") must be removed by refactoring.

A retained directive needs:

- a specific linter name (`//nolint:errcheck`, not `//nolint`);
- a genuine, local reason the rule cannot be satisfied without harming
  correctness, wire compatibility, or an intentional lifecycle boundary;
- plain ASCII explanation on the same line or immediately above.

Do not add a suppression to avoid refactoring. If the code can conform, make
it conform.

`.golangci.yml` enables `nolintlint` with `require-explanation: true` and
`require-specific: true`.

As of the standing inventory, the repository retains 342 `//nolint`
directives: 222 under `internal/`, 119 under `tests/`, and 1 under `cmd/`.
Suppressions are spread across production and test packages rather than
clustered in one tree; the largest single-package concentration is
`tests/integration` (81 directives in 28 files). All are governed by
`nolintlint` with `require-explanation` and `require-specific` (each
directive names a specific linter and carries a rationale), so the standing
set is auditable rather than tacit.

## Removed temporary exclusions

Earlier `.golangci.yml` scaffolding excluded cyclop on test paths, `noctx`
on test and integration paths, and gosec on test paths. That scaffolding
was temporary while tests were refactored to meet the full bar. After the
test refactors landed, the temporary exclusions were removed. Findings newly
surfaced by removal were burned down under the same refactor-first bar as
production code; no replacement test-path waivers were added.

## Gosec global excludes

`.golangci.yml` sets global gosec excludes (not inline `//nolint` directives)
so accepted-as-is findings are auditable in one place:

- **G304**: paths are config-controlled, not user input.
- **G306**: 0644 is correct for public certs; private keys use 0600.
- **G104**: best-effort cleanup; meaningful errors are covered by errcheck.
  `.golangci.yml` `exclusions.rules` also carries a gosec G104 text
  exclusion for residual matches.
- **G101**: matches reason-code strings and test-fixture labels, not real
  secrets; real secrets are env/config-injected.
- **G115**: conversions are over fixed small values (lengths, argon2 params);
  no unbounded input.

## Retained justified categories

The following categories are the only standing reasons to keep inline
directives once refactor options are exhausted.

### Production errcheck after WriteHeader

After `WriteHeader`, the HTTP response is committed. A subsequent body write
error cannot be recovered or meaningfully handled. Retained `errcheck` (and
paired `errchkjson` where applicable) on encode/write lines that follow
`WriteHeader` must state that the response is already committed.

### tagliatelle wire-format exceptions

`tagliatelle` enforces camelCase JSON struct tags. Retained exceptions are
limited to wire names mandated by external specs:

- RFC 6749 OAuth 2.0 token endpoint fields in snake_case (`grant_type`,
  `client_id`, `access_token`, `token_type`, `expires_in`,
  `error_description`, and similar).
- OCM-API `userID` (capital `ID`), not camelCase `userId`.

OCM fields that already match camelCase (`apiVersion`, `endPoint`, and
similar) need no `tagliatelle` suppression.

### nilnil skip sentinels

`(nil, nil)` returns where nil is the intentional skip or no-op result under
the caller contract (for example TLS mode off, crypto skipped, no extra CA
roots). The explanation must name what nil denotes and how the caller
branches.

### contextcheck retained categories

`contextcheck` flags sites that do not thread or derive `context.Context`.
Retained suppressions fall into four categories; all others should be fixed
by passing context, not suppressed.

- Detached startup goroutines that intentionally outlive the request context
  and manage their own boundary (for example `srv.Start()` with an internal
  lifecycle context). Threading the request context would change public
  signatures without benefit.
- Test-helper APIs that accept no context parameter (for example the JSON
  store `makeDriver` open helper). The helper signature has no context to
  thread; the directive names that constraint.
- Middleware closures that already capture and reuse the request context
  directly (`r.Context()`), where no separate context exists to thread.
- Fixed-signature callback fetchers (for example the `VerifyRequest` key
  fetcher) whose signature is fixed by an external interface and accepts no
  context.

### gosec on controlled local httptest fixtures

False positives on paths, permissions, redirects, subprocess launch, or TLS
settings that exist only inside local test servers and fixtures. The comment
must name the controlled constraint (local test server, developer-set env
var, self-signed test CA, and similar), not claim production safety.

### Justified test scaffolding

Intentional httptest redirects, fake secrets on controlled test servers,
and expected-error teardown (`Wait` after `Kill`, `Signal` on an exiting
process) logged via `t.Logf` rather than failed. Fixture seeding must
thread `*testing.T` and check errors via `t.Fatal`/`t.Errorf`; it is not a
justified suppression. The comment must name the real test constraint
being exercised, not a generic "test only" excuse.

### Parallel-case dupl directives

`dupl` is info severity but still signals copy-paste debt. Retained `dupl`
directives are allowed only where parallel tests or helpers share near-
identical setup but assert different outcomes. The comment must name the
different outcomes or failure scenarios (for example different OAuth errors,
different reason codes, different configured paths).

The standing set includes exactly two parallel-case `dupl` suppressions for
entity-specific delete rollback helpers in the JSON store durability tests:
one for incoming invite rollback and one for incoming share rollback. They
share the read-only-dir rollback pattern but cover different store
interfaces, method sets, and index semantics.

Unused `//nolint:dupl` directives (no matching dupl finding) are lint
violations and must be removed or justified by an actual duplicate block.

## Comment quality

Suppression comments must be accurate:

- Do not claim false nil-slice semantics (for example calling a non-nil empty
  slice "nil").
- Do not describe restrictive permissions as permissive.
- Do not embed planning or task metadata (wave labels, batch ids, ticket
  breadcrumbs).

## Adding new suppressions

New suppressions require genuine justification and an accurate ASCII
explanation. Review against the categories above. If none apply, refactor
instead.

## zizmor workflow security

CI runs zizmor via `.github/workflows/ci-security-zizmor.yml` with config in
`.github/zizmor.yml`. The blocking gate is `zizmor --min-severity high .`:
high-severity workflow findings (SARIF "error" level) fail the security job.
Medium and lower severities are non-blocking. Both CI zizmor runs (the SARIF
artifact upload and the gating run) use `--min-severity high`, so only
high-severity findings are emitted.

`unpinned-uses` is disabled in `.github/zizmor.yml` because SHA-pinning of
GitHub Actions is owned by `make verify-action-pins`
(`.github/scripts/verify-action-pins.nu`); zizmor does not double-enforce pins.

## Hygiene linters

markdownlint, typos, hadolint, and yamllint are hygiene gates separate from
golangci-lint. The markdownlint gate runs rumdl (a Rust markdown linter,
drop-in for markdownlint-cli2); markdownlint, hadolint, and yamllint run via
their make targets (`make markdownlint`, `make hadolint`, `make yamllint`).
The typos CI job uses the crate-ci/typos action directly (pinned in
`.github/action-pins.yml`, config `.typos.toml`). As pre-commit hooks
(`.pre-commit-config.yaml`), all four call their matching `make <target>`
(`entry: make <target>`). The Makefile pins versions for the make-backed
linters (rumdl, yamllint, hadolint, typos); the typos CI job is the exception
(action-pinned).

Accepted suppressions:

- **hadolint**: `.hadolint.yaml` ignores DL3008 because the Debian build and
  runtime stages rely on the distribution's supported package set, not
  per-package version pins.
- **markdownlint (rumdl)**: hierarchical `.rumdl.toml`. Root `.rumdl.toml`
  disables MD013 (line length, not a doc-correctness gate), MD034 (bare URLs
  allowed), MD060, and restricts MD033 to `allowed_elements` p, a, img, and
  excludes `node_modules/`. `.github/.rumdl.toml` and `.changes/.rumdl.toml`
  extend the root and additionally disable MD041 (templates and release notes
  are embedded snippets, not standalone documents with a top-level title).

Contributor prerequisites: yamllint runs via `uvx yamllint==<pin>` (Makefile
pin) and auto-fetches, so it needs no manual install. rumdl (Rust), typos
(Rust), and hadolint (Haskell) are PATH binaries; `make markdownlint`,
`make typos`, and `make hadolint` exit non-zero if the binary is missing.
Contributors who install the pre-commit hooks must have rumdl, typos, and
hadolint on PATH (install once from their GitHub releases; CI installs rumdl
and hadolint directly per `.github/workflows/ci-lint-rumdl.yml` and
`.github/workflows/ci-lint-hadolint.yml`).

## Verification

Run these from the repository root when validating lint policy compliance:

```sh
make lint
go test ./...
go build ./...
gofmt -l .
go vet ./...
make markdownlint
make typos
make hadolint
make yamllint
uv run reuse lint
uv run pre-commit run --all-files
```

A clean `make lint` is the golangci-lint gate. `go test ./...` exercises the
full module including integration tests. `gofmt -l .` must produce no output.
The four `make markdownlint`, `make typos`, `make hadolint`, and
`make yamllint` commands run the hygiene gates directly (see the Hygiene
linters section for PATH prerequisites). Pre-commit covers gofmt, goimports, go vet, go mod tidy, golangci-lint, unit
tests, shellcheck, actionlint, the hygiene quartet (markdownlint, typos,
hadolint, yamllint), and REUSE - the Go, shell, workflow, hygiene, and
licensing gates. The hygiene quartet runs in CI and as pre-commit hooks (each
calling the matching `make <target>`); yamllint auto-fetches via uvx, while
rumdl, typos, and hadolint require a PATH install (see the Hygiene linters
section above).

Related: [development.md](development.md), [testing.md](testing.md),
[CONTRIBUTING.md](../CONTRIBUTING.md).
