<!--
SPDX-License-Identifier: AGPL-3.0-or-later
SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>

OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.
-->

# Contributing

Thanks for taking a look at OpenCloudMesh Go. Fixes, new tests, doc
clean-ups, and questions are all welcome, and none of them are too small to
send.

To get your bearings, these four docs are the best starting point:

- [docs/development.md](docs/development.md) for the local workflow
- [docs/testing.md](docs/testing.md) for how the test layers fit together
- [docs/architecture.md](docs/architecture.md) for how the code is organized
- [docs/naming-conventions.md](docs/naming-conventions.md) for the conventions
  the guard tests enforce

## Where to start

If you are not sure where to jump in, a few low-risk places tend to be
friendly: tightening or adding tests around the strict contract, improving docs
that tripped you up while getting started, or picking up something from the
[issue tracker](https://github.com/MahdiBaghbani/opencloudmesh-go/issues). If
you are planning a larger change, opening an issue first to talk it through
saves everyone time.

One heads-up: the code has architecture guard tests that enforce layering and
naming. If `make test` complains about an import boundary, that is the guard
doing its job, and [docs/architecture.md](docs/architecture.md) explains the
rules.

## Small tasks for new contributors

If you are new to the project, look for issues labeled `good first issue` and
`help wanted` in the
[issue tracker](https://github.com/MahdiBaghbani/opencloudmesh-go/issues).
These are scoped to be approachable without a deep understanding of the whole
codebase.

Typical small tasks that are friendly to new or casual contributors:

- Add or tighten unit tests around the strict contract paths (see
  [docs/testing.md](docs/testing.md)).
- Fix typos or clarify docs that tripped you up while getting started.
- Add examples to existing docs.
- Pick up a `good first issue` and send a small focused PR.

If you want to work on something but no issue matches, open an issue first so
we can scope it together before you start.

## Git hooks (pre-commit)

Pre-commit runs a fail-closed check set before each commit. Any hook
failure blocks the commit.

| Hook | Scope | CI mirror |
| ---- | ----- | --------- |
| gofmt | staged `.go` (index) | `make fmt-check` |
| goimports | staged `.go` (index) | `make fmt-check` |
| go-vet | full module (index snapshot) | `make vet` |
| go-mod-tidy | `go.mod` / `go.sum` vs index | fmt-vet tidy step |
| golangci-lint | full module | `make lint` |
| go-test-unit | full module, `-race`, excludes `tests/integration` | `make test-go` |
| shellcheck | staged shell scripts | CI shellcheck job |
| actionlint | `.github/workflows` when a workflow file is staged | pre-commit only |
| markdownlint | full tree (rumdl) | `make markdownlint` / CI markdownlint job |
| typos | full tree | `make typos` / CI typos job |
| hadolint | `docker/Dockerfile` + `.hadolint.yaml` | `make hadolint` / CI hadolint job |
| yamllint | non-workflow YAML | `make yamllint` / CI yamllint job |
| reuse | full tree | `make reuse-lint` / CI reuse job |

Local hooks under `scripts/git/` are Nushell helpers invoked by
pre-commit (`nu scripts/git/pre-commit-*.nu`). `go-test-unit` calls
`make test-go` directly so its package list and `-race` flag stay in
sync with CI.

### Conditional parity with CI

A green local pre-commit run is meaningful: every hook that ran passed.
It does **not** guarantee every CI job passed on its own.

- Hooks with `types: [go]` (gofmt, goimports, go-vet, golangci-lint)
  skip when the commit has no staged Go files. Docs-only commits can
  still fail reuse or go-mod-tidy, but golangci-lint is skipped while CI
  lint still runs on the full tree.
- gofmt and goimports check only staged `.go` files; a passing hook does
  not guarantee `make fmt-check` passes on the whole tree if unstaged
  files are misformatted.
- go-test-unit, go-mod-tidy, and reuse run on every commit attempt
  (they are not gated on staged Go files).
- shellcheck runs only when staged files include shell scripts
  (`types: [shell]`); it skips commits with no staged shell files.
- actionlint runs only when a staged file matches
  `.github/workflows/**/*.{yml,yaml}`; it skips commits with no staged
  workflow file.
- Pre-commit does not run integration tests, E2E, security scans, build,
  or action-pin verification. Run `make ci` or push to CI for those.

### uv-managed setup

Python tooling is pinned in `pyproject.toml` (`pre-commit`, `reuse`) and
installed into `.venv` by [uv](https://docs.astral.sh/uv/):

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh   # install uv
uv sync                         # create .venv from pyproject.toml / uv.lock
make tools                      # pinned goimports + golangci-lint (Makefile)
make pre-commit-install         # writes .git/hooks/pre-commit
```

Nushell (`nu`) is required for the staged Go helpers. Install via
[mise](https://mise.jdx.dev/) or the
[official Nushell install](https://www.nushell.sh/book/installation.html).

[shellcheck](https://www.shellcheck.net/) and
[actionlint](https://github.com/rhysd/actionlint) must be on `PATH` for
pre-commit (shellcheck for shell scripts; actionlint for workflow files).
The hygiene linters [rumdl](https://github.com/rvben/rumdl) (the markdownlint
gate), [typos](https://github.com/crate-ci/typos), and
[hadolint](https://github.com/hadolint/hadolint) must also be on `PATH`;
`make markdownlint`, `make typos`, and `make hadolint` exit non-zero if the
binary is missing. yamllint auto-fetches via `uvx` and needs no manual install.
CI runs shellcheck and actionlint; CI installs rumdl and hadolint directly.

Optional manual run before commit:

```sh
make pre-commit-run
# or: uv run pre-commit run --all-files
```

Hook versions for Go tools match CI via `make tools` (`GOLANGCI_LINT_VERSION`,
`GOIMPORTS_VERSION` in the Makefile). REUSE uses the pinned upstream
pre-commit hook (`fsfe/reuse-tool` at `v6.2.0`).

When this repository lives inside a MAIDE meta workspace, invoke MAIDE
from the workspace root as `nu scripts/maide.nu <domain> ...`. This
satellite still installs and runs pre-commit from its repository root
with `make pre-commit-install` and `make pre-commit-run` (or `cd
repos/opencloudmesh-go` first when your shell cwd is the meta root).

The legacy `.githooks/pre-commit` path is retired; use pre-commit install
instead.

## Before you open a pull request

Run the smallest relevant checks for your change. In most cases that means:

```sh
make fmt-check
make vet
make lint
make test
```

With hooks installed, `git commit` runs the pre-commit check set (see
above). Staged Go hooks and golangci-lint skip when no `.go` files are
staged; go-mod-tidy, go-test-unit, and reuse still run.

If your change touches browser flows, invite UX, or WAYF behavior, also run:

```sh
make test-e2e-install
make test-e2e
```

## A few expectations

- Keep pull requests focused and easy to review.
- Explain the problem you are solving, not just the diff.
- Mention any follow-up work if the change is intentionally partial.
- Update the docs when behavior changes.

## Code review

All changes land through pull requests on GitHub. This section documents how
review is conducted, what must be checked, and what is required for a change to
be acceptable.

How review is conducted:

- Changes are proposed as pull requests against `master`.
- Review happens on the GitHub pull request, comment by comment.
- The maintainer reviews the diff; CI runs the automated gate set on every push
  to the pull request.

What must be checked before a change is acceptable:

- `make ci` is green (fmt, vet, lint, tests, security scans, licenses, reuse,
  action pins, file-length, markdownlint). See the `ci` target in the Makefile.
- Architecture guard tests pass; no forbidden import boundaries are introduced
  (see [docs/architecture.md](docs/architecture.md)).
- Tests cover new or changed behavior, and existing tests still pass.
- Docs are updated when behavior changes.
- The pull request is focused and explains the problem it solves.

A change is acceptable when all CI checks pass, review comments are resolved,
and the maintainer approves the merge. The project currently has a single
maintainer, so human review is by the maintainer and CI is the automated
reviewer; see [MAINTAINERS.md](MAINTAINERS.md) and
[GOVERNANCE.md](GOVERNANCE.md) for roles and the succession plan.

By contributing, you agree that your contributions are licensed under
AGPL-3.0-or-later, consistent with this repository.
