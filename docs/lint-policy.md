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

Production and test code share the same lint standard unless an explicit
linter-specific setting says otherwise. Tests are not a second-class
surface: enabled linters still run with the same severity rules. The
goconst and mnd test-file settings are documented below because test
files (`*_test.go`) and idiomatic test values do not benefit from those checks.

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

As of the standing inventory, the repository retains 383 `//nolint`
directives: 268 under `internal/`, 111 under `tests/`, and 4 under `cmd/`.
Suppressions are spread across production and test packages rather than
clustered in one tree; the largest single-package concentration is
`tests/integration` (108 directives in 33 files). All are governed by
`nolintlint` with `require-explanation` and `require-specific` (each
directive names a specific linter and carries a rationale), so the standing
set is auditable rather than tacit.

## Disabled linters (global)

Seventeen linters are disabled globally in `.golangci.yml`. One of them
needs a narrative rationale beyond its inline config comment; the entry
below documents that linter. The remaining sixteen disabled linters carry
their rationale as inline comments in `.golangci.yml`.
Unlike the gosec scoped exclusions (which run the linter and suppress accepted
findings), this one does not run at all. The entry states whether the
disable is structural (needs an architectural change to turn on), deferred
(has a concrete burn-down trigger), or permanent (a deliberate style choice
with no burn-down trigger). None of these are "too noisy" or "will fix
later" waivers; both phrases are banned by the Refactor-first suppressions
section above.

### err113 - deferred

`err113` (define errors as package-level sentinels) is deferred. It has no
settings knob in golangci-lint v2.12.2 and roughly 308 production hits, so
a blanket enable would surface hundreds of findings with no way to narrow
them. Burn-down trigger: a phased
sentinel-extraction program that lifts repeated `errors.New` literals to
package-level sentinels, paired with `errname` for stable error names.

## Repeated string literals (goconst)

`goconst` is enabled with `ignore-tests: true`. Repeated production string
literals are extracted into package-local named constants, while test
files (`*_test.go`) are excluded because test-data strings are idiomatic
as literals and extracting them obscures test intent.

## Magic numbers (mnd)

`mnd` is enabled with `ignored-files: [".*_test\\.go"]` (test files excluded,
matching goconst) and an allowlist for idiomatic values. The allowlist covers
common file permissions and small integers used as indices, counts, retries,
timeouts, buffer sizes, key sizes, and bit operations. Only genuine magic
numbers, such as HTTP status codes, service ports, and byte masks, require
named constants.

## Function ordering (funcorder)

`funcorder` is enabled across the project with its default settings. It checks
that each constructor (a `New`/`Must` function returning a struct declared in the
same file) is placed after that struct's declaration, and that a struct's
exported methods come before its non-exported methods. Alphabetical sorting and
standalone-function ordering are off by default. The team adopted this ordering
convention, reversing the prior permanent-disable decision.

## Test parallelism (paralleltest)

`paralleltest` is enabled across the project. Every test function and
table-driven range loop must call `t.Parallel()` so tests run concurrently.

A test that cannot run in parallel carries a specific `//nolint:paralleltest`
with an ASCII reason. The standing set is 32 directives, each verified
empirically: the directive was removed and the `paralleltest` finding
confirmed at its exact line before the directive was restored. They fall
into six categories, all backed by a real process-global or shared-state
hazard: 17 tests use `t.Setenv` (1 calls it directly; 16 reach it through a
helper - `loadJwksURITOML` or `loadTLSPathConfig`), which mutates
process-global env and panics with `t.Parallel` by Go runtime design; 3
tests call `t.Chdir` directly, which mutates process-global cwd the same
way; 3 table-driven range loops run subtests against a parent that has
already mutated process-global env or cwd, so the subtests share the mutated
baseline; 6 directives across 3 tests serialize subtests that call
`slog.SetDefault`, mutating the process-global default logger; 2 directives
(test function and range loop) serialize one test that mutates
process-global proxy env via raw `os.Setenv`/`os.Unsetenv`, which
`paralleltest` does not detect because it only recognizes `t.Setenv` and
`t.Chdir`; and 1 test mutates a package-level wiring hook restored in
`t.Cleanup`. Each directive names the specific shared resource.

`paralleltest` does not flag a test merely because it calls `t.Setenv` or
`t.Chdir` indirectly through a subtest closure, so those tests need no
directive; a directive is added only where `paralleltest` actually reports a
missing `t.Parallel()` and the test genuinely cannot run concurrently.
Earlier bulk passes over-applied directives to tests `paralleltest` does not
flag; an empirical pass removed 115 such redundant directives, leaving 26
honest suppressions at the time; later race-hazard fixes serialized the
`slog.SetDefault` and raw proxy-env tests, bringing the standing set to the
32 directives above.

One avoidable `t.Chdir` suppression was refactored instead of suppressed:
`TestBootstrapAdmin_WritesGeneratedPasswordFile` now sets an absolute
`Server.BootstrapAdmin.CredentialFile` and runs in parallel with no nolint.

Root-cause hardening: `internal/testsupport/modroot/modroot.go` `ModuleRoot`
and `tests/integration/harness/subprocess.go` `FindProjectRoot` previously
resolved the module root via `os.Getwd()` (process-global CWD), which raced
with the integration harness `os.Chdir` when subtests ran in parallel. Both
now resolve the caller's source file via `runtime.Caller` and walk up to
`go.mod`, making them CWD-independent and parallel-safe. This repo does not
build with `-trimpath`, so `runtime.Caller` returns absolute paths.

Note: the integration harness (`tests/integration/harness/subprocess.go`
`loadEffectiveSubprocessConfig`) still mutates process-global `os.Chdir`
and `os.Setenv` under `subprocessChdirMu` for config loading; the
CWD-independent module-root resolution above removes the parallel race this
previously caused, so integration subtests can run in parallel. A future
burn-down is to isolate subprocess config loading to the child process only
(no parent `os.Chdir`/`os.Setenv`), which would let the remaining
`t.Setenv`/`t.Chdir` integration tests drop their nolints too.

## Error wrapping (wrapcheck)

`wrapcheck` is enabled. Every error returned from an external package
(stdlib or another package) must be wrapped with `fmt.Errorf` and `%w`
so the call site adds context and the chain stays inspectable via
`errors.Is` and `errors.As`.

Voice convention: `<subsystem>: <verb> <noun>: %w`. The subsystem
prefix names the current layer (for example `store`, `crypto`, `http`,
`repos`, `identity`, `ocm`, `api`, `services`, `wiring`, `config`,
`testsupport`, `tests`). The verb and noun describe the operation
(for example `store: open database: %w`, `crypto: sign message: %w`,
`http: read response body: %w`). Lowercase, no trailing period, a
single colon-space after the subsystem, and `%w` (never `%v` or `%s`).

Same-subsystem different-operation chains (for example
`store: update outgoing invite: store: apply outgoing invite update: %w`)
are intentional: each layer tags its own subsystem plus its concrete
operation, so the chain records every stage. A repeated subsystem prefix
with different operations is not a duplicate; it is hierarchical stage
tagging.

`//nolint:wrapcheck` is reserved for sites where wrapping would break
sentinel detection. The one accepted case is
`internal/platform/store/json/io.go`, where the raw `os.ReadFile` error is
returned unwrapped so callers' `os.IsNotExist` detects a missing file during
initialization; the directive carries an explanation comment. Do not add
`//nolint:wrapcheck` for convenience or noise.

## Generated disable inventory

The block below is generated from `.golangci.yml` by
`nu .github/scripts/lint-policy-drift-check.nu --write`. It mirrors the
disabled-linter list and the sibling policy knobs (linters.default,
linters.disable,
govet.disable, staticcheck.checks, gosec.excludes, exclusions.generated,
exclusions.presets, exclusions.rules, nolintlint, tagliatelle, cyclop,
errcheck, revive, errchkjson, modernize, goimports.local-prefixes, issues,
severity, run.modules-download-mode) so a silent change to any of them shows
up as drift.
CI runs the script in check mode and fails on drift; do not edit the block by
hand.

<!-- golangci-disable-inventory:begin -->
<!-- Generated by `nu .github/scripts/lint-policy-drift-check.nu --write`; .golangci.yml is the SSOT. Do not edit by hand. -->

```yaml
run:
  modules-download-mode: readonly
linters:
  default: all
  disable:
    - wsl
    - depguard
    - exhaustruct
    - noinlineerr
    - varnamelen
    - err113
    - lll
    - testpackage
    - funlen
    - gochecknoglobals
    - nestif
    - gocognit
    - gomodguard
    - nonamedreturns
    - ireturn
    - gochecknoinits
    - gocyclo
  settings:
    cyclop:
      max-complexity: 15
      package-average: 0
    errcheck:
      check-type-assertions: true
      check-blank: true
      disable-default-exclusions: true
      verbose: true
      exclude-functions: []
    govet:
      enable-all: true
      disable:
        - fieldalignment
    modernize:
      disable:
        - stringsseq
    staticcheck:
      checks:
        - all
        - -ST1000
        - -ST1003
    revive:
      enable-all-rules: false
      rules:
        - name: unused-parameter
        - name: error-return
        - name: indent-error-flow
        - name: var-naming
        - name: exported
          arguments:
            - disableStutteringCheck
    errchkjson:
      check-error-free-encoding: true
      report-no-exported: false
    nolintlint:
      require-explanation: true
      require-specific: true
    tagliatelle:
      case:
        rules:
          json: camel
    gosec:
      excludes: []
  exclusions:
    generated: strict
    presets: []
    rules:
      - linters:
          - gosec
        text: "G104:"
      - path: _test\.go$|^tests/|/testsupport/
        linters:
          - gosec
        text: "G30[46]:|G101:"
      - path: internal/platform/crypto/
        linters:
          - canonicalheader
      - path: internal/platform/cache/memory/memory\.go
        linters:
          - revive
        text: 'unused-parameter: parameter ''ctx'''
      - linters:
          - modernize
        text: Goroutine creation can be simplified using WaitGroup.Go
      - linters:
          - modernize
        text: var requestCount int32 may be simplified using atomic.Int32
      - path: internal/testsupport/http/proxyenv\.go
        linters:
          - usetesting
        text: ^os\.Setenv\(\) could be replaced by tb\.Setenv\(\) in ClearProxyEnv$
formatters:
  settings:
    goimports:
      local-prefixes:
        - github.com/MahdiBaghbani/opencloudmesh-go
issues:
  max-issues-per-linter: 0
  max-same-issues: 0
  uniq-by-line: true
severity:
  default: error
  rules:
    - linters:
        - misspell
        - dupl
      severity: info
```

<!-- golangci-disable-inventory:end -->

## Removed temporary exclusions

Earlier `.golangci.yml` scaffolding excluded cyclop on test paths, `noctx`
on test and integration paths, and gosec on test paths. That scaffolding
was temporary while tests were refactored to meet the full bar. After the
test refactors landed, the temporary exclusions were removed. Findings newly
surfaced by removal were burned down under the same refactor-first bar as
production code; no replacement exclusions were added for those scaffolding
rules. The goconst and mnd test-file settings are separate linter policies
documented above.

## Gosec scoped policy

Gosec is enabled with `linters.default: all` and no global gosec rule
excludes. Accepted findings are scoped in `.golangci.yml` or documented
inline `//nolint:gosec` directives on production sites.

**G104 text exclusion.** Residual G104 matches are suppressed by the
unchanged `exclusions.rules` entry `text: "G104:"` because G104 is redundant
with strict errcheck for meaningful errors. Remaining G104 sites are
best-effort cleanup such as deferred `Close` and `WriteHeader`-adjacent
writes.

**Test and testsupport path exclusion.** G304, G306, and G101 findings in test
files and test-support code are suppressed by a path-scoped
`exclusions.rules` entry (`path: '_test\.go$|^tests/|/testsupport/'`,
`text: G30[46]:|G101:`). The path regex matches every `*_test.go` file
wherever it lives in the tree, plus the non-test harness and support code under
`tests/` and `internal/testsupport/`. Those sites are test fixtures:
config-derived paths, test-file permissions, and fake secrets on controlled
test servers.

**Production inline nolints and fixes.** Real production G304, G306, G101,
and G115 sites carry inline `//nolint:gosec` directives naming the accepted
constraint, or a safe fix. The PR8 audit identified 14 production findings
(10 G304, 2 G306, 1 G101, 1 G115); the implementation is 13 inline
directives plus one fix: 10 G304 inline nolints, 2 G306 inline nolints, 1
G101 inline nolint, and G115 fixed with a bounds check rather than
suppressed. Per-code rationale:

- **G304**: paths are config-controlled, not user input.
- **G306**: 0644 is correct for public certs; private keys use 0600.
- **G101**: matches reason-code strings and test-fixture labels, not real
  secrets; real secrets are env/config-injected.
- **G115**: the one production site was fixed with a bounds check; no G115
  inline nolint exists.

Test fixtures live throughout the tree, not only under `tests/` and
`internal/testsupport/`, so the path-scoped exclusion matches `*_test.go`
files everywhere. No per-test inline `//nolint:gosec` directives are
added; the zero-issue lint result for the test tree comes from this path
scope, not from silent global suppression.

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
