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

## Before you open a pull request

Run the smallest relevant checks for your change. In most cases that means:

```sh
make fmt
make vet
make test
```

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
