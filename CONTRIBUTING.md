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

## Git hooks (pre-commit)

gofmt, goimports, and go vet hooks check **staged** `.go` files only using
the staged-content contract. The golangci-lint hook runs the **full** module
lint, mirroring `make lint` / CI, when the commit includes staged Go files.
It is skipped for docs-only commits (no staged `.go` files) because of
`types: [go]`. A green local pre-commit means staged files passed fmt/vet
checks; for commits that touch Go files it also means full-module lint
passed (CI lint should match). For docs-only commits the lint hook is
skipped and CI lint must still pass independently. A green local
pre-commit does not guarantee whole-tree CI fmt or vet.

One-time setup:

Nushell (`nu`) is required because the pre-commit helpers are `.nu` files.
Install via [mise](https://mise.jdx.dev/) or the
[official Nushell install](https://www.nushell.sh/book/installation.html).

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh   # install uv
uv sync                   # create .venv and install pinned pre-commit from uv.lock
make tools                # pinned goimports + golangci-lint (see Makefile)
make pre-commit-install   # writes .git/hooks/pre-commit (uses the project venv)
```

Optional manual run before commit:

```sh
make pre-commit-run
```

Hook versions match CI via `make tools` (`GOLANGCI_LINT_VERSION`,
`GOIMPORTS_VERSION` in the Makefile). The legacy `.githooks/pre-commit`
path is retired; use `pre-commit install` instead.

## Before you open a pull request

Run the smallest relevant checks for your change. In most cases that means:

```sh
make fmt-check
make vet
make lint
make test
```

With hooks installed, `git commit` runs staged gofmt/goimports/vet plus the
full-module golangci-lint bar for Go paths you are committing.

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

By contributing, you agree that your contributions are licensed under
AGPL-3.0-or-later, consistent with this repository.
