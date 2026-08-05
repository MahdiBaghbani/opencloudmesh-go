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

## Removed temporary exclusions

Earlier `.golangci.yml` scaffolding excluded cyclop on test paths, `noctx`
on test and integration paths, and gosec on test paths. That scaffolding
was temporary while tests were refactored to meet the full bar. After the
test refactors landed, the temporary exclusions were removed. Findings newly
surfaced by removal were burned down under the same refactor-first bar as
production code; no replacement test-path waivers were added.

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

## Verification

Run these from the repository root when validating lint policy compliance:

```sh
make lint
go test ./...
go build ./...
gofmt -l .
go vet ./...
uv run reuse lint
uv run pre-commit run --all-files
```

A clean `make lint` is the golangci-lint gate. `go test ./...` exercises the
full module including integration tests. `gofmt -l .` must produce no output.
Pre-commit covers gofmt, goimports, go vet, go mod tidy, golangci-lint, unit
tests, shellcheck, actionlint, and REUSE - the Go, shell, workflow, and
licensing gates. The hygiene quartet (markdownlint, typos, hadolint, yamllint)
runs in CI and is available locally via `make markdownlint`, `make typos`,
`make hadolint`, and `make yamllint` (prerequisites: `make hygiene-tools`); it
is intentionally not a pre-commit hook so contributors are not forced to
install bun, uv, typos, and hadolint.

Related: [development.md](development.md), [testing.md](testing.md),
[CONTRIBUTING.md](../CONTRIBUTING.md).
