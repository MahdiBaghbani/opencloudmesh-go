# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
#
# OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

# OpenCloudMesh server build and test targets.
SHELL := /bin/bash
.PHONY: build test-go test-integration test-e2e test-e2e-install \
	test clean fmt fmt-check vet tidy tools lint lint-fix lint-new shellcheck \
	actionlint security licenses licenses-check licenses-save licenses-install check ci \
	pre-commit-install pre-commit-run \
	generate-action-inventory verify-action-pins reuse-lint \
	markdownlint markdownlint-fix typos hadolint yamllint hygiene-tools

# Version embedded into binaries via -ldflags; falls back to "dev" outside git.
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Build the server binary
build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/opencloudmesh-go ./cmd/opencloudmesh-go

# Run unit tests with race detector (excludes integration tests)
test-go:
	go test -race -coverpkg=./internal/...,./cmd/... -coverprofile=coverage-unit.out $$(go list ./... | grep -v /tests/integration)

# Run integration tests only
test-integration:
	go test -race -coverpkg=./internal/...,./cmd/... -coverprofile=coverage-integration.out ./tests/integration/...

# Install E2E test dependencies
test-e2e-install:
	cd tests/e2e && bun install && bun run install:browsers

# Run E2E tests with Playwright
test-e2e: build
	cd tests/e2e && bun run test

# Run all tests (excluding E2E - run separately with test-e2e)
test: test-go test-integration

# Clean build artifacts
clean:
	rm -rf bin/
	rm -rf tests/e2e/node_modules
	rm -rf tests/e2e/test-results
	rm -rf tests/e2e/playwright-report/
	rm -f coverage-unit.out coverage-integration.out

# --- Static analysis and security (requires: make tools) ---

GOLANGCI_LINT_VERSION ?= v2.12.2
GOVULNCHECK_VERSION ?= v1.1.4
GOIMPORTS_VERSION ?= v0.30.0
ACTIONLINT_VERSION ?= v1.7.12
GO_LICENSES_VERSION ?= v2.0.1
# Hygiene tools: bunx/uvx pin npm/PyPI versions; typos/hadolint are PATH binaries.
MARKDOWNLINT_CLI2_VERSION ?= 0.23.2
YAMLLINT_VERSION ?= 1.38.0
TYPOS_VERSION ?= v1.49.0
HADOLINT_VERSION ?= v2.15.1

GOLANGCI_LINT ?= golangci-lint
GOVULNCHECK ?= govulncheck
GOIMPORTS ?= goimports
ACTIONLINT ?= actionlint
GO_LICENSES ?= go-licenses
# bunx --bun runs the pinned npm package without a root package.json.
MARKDOWNLINT ?= bunx --bun markdownlint-cli2@$(MARKDOWNLINT_CLI2_VERSION)
TYPOS ?= typos
HADOLINT ?= hadolint
HADOLINT_FLAGS ?= -c .hadolint.yaml
YAMLLINT ?= uvx yamllint==$(YAMLLINT_VERSION)

# Non-workflow YAML only; .github/workflows/** is owned by actionlint.
YAMLLINT_PATHS := .changie.yaml .pre-commit-config.yaml .golangci.yml \
	.hadolint.yaml .github/dependabot.yml .github/action-pins.yml .changes \
	.github/.markdownlint.yaml .github/ISSUE_TEMPLATE

# Linked-tree license scan scope (single binary under cmd/).
GO_LICENSES_PKG ?= ./cmd/opencloudmesh-go
LICENSES_ALLOWLIST ?= .github/licenses-allowlist.txt
LICENSES_SAVE_PATH ?= bin/licenses
# Own module is AGPL; go-licenses save treats AGPL as forbidden, so ignore it
# when collecting third-party NOTICE/LICENSE files for the image artifact.
GO_LICENSES_IGNORE ?= github.com/MahdiBaghbani/opencloudmesh-go

# Comma-separated allowlist for go-licenses check (skip blank/# comment lines).
ALLOWED_LICENSES = $(shell grep -vE '^\s*(#|$$)' $(LICENSES_ALLOWLIST) | paste -sd, -)

# Install pinned CLIs into GOBIN (no @latest). gosec runs via golangci-lint
# SSOT only; no standalone gosec binary.
tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)
	go install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)
	go install github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION)

# Hygiene tool prerequisites (not go-installable). markdownlint-cli2 via bunx;
# yamllint via uvx; typos (Rust) and hadolint (Haskell) must be on PATH.
# See https://github.com/crate-ci/typos/releases and
# https://github.com/hadolint/hadolint/releases (pins: TYPOS_VERSION / HADOLINT_VERSION).
hygiene-tools:
	@command -v bun >/dev/null 2>&1 || (echo "bun not found; install from https://bun.sh"; exit 1)
	@command -v uvx >/dev/null 2>&1 || (echo "uv/uvx not found; install from https://docs.astral.sh/uv/"; exit 1)
	@command -v $(TYPOS) >/dev/null 2>&1 || (echo "typos not found; install $(TYPOS_VERSION) from https://github.com/crate-ci/typos/releases"; exit 1)
	@command -v $(HADOLINT) >/dev/null 2>&1 || (echo "hadolint not found; install $(HADOLINT_VERSION) from https://github.com/hadolint/hadolint/releases"; exit 1)
	@echo "hygiene-tools: bun=$$(bun --version) typos=$$($(TYPOS) --version) hadolint=$$($(HADOLINT) --version)"
	@echo "hygiene-tools: markdownlint-cli2@$(MARKDOWNLINT_CLI2_VERSION) via bunx; yamllint==$(YAMLLINT_VERSION) via uvx"

# Install only go-licenses (focused; CI licenses jobs call this so the version SSOT stays in the Makefile).
licenses-install:
	go install github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION)

# Mutating format: go fmt + goimports (matches pre-commit gofmt/goimports hooks).
fmt:
	go fmt ./...
	$(GOIMPORTS) -w .

# Fail if any file needs gofmt or goimports (CI-safe; unlike fmt which mutates).
fmt-check:
	@command -v $(GOIMPORTS) >/dev/null 2>&1 || (echo "goimports not found; install with: make tools"; exit 1)
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed; run: make fmt"; exit 1)
	@test -z "$$($(GOIMPORTS) -l .)" || (echo "goimports needed; run: make fmt"; exit 1)

# Vet code
vet:
	go vet ./...

# Tidy dependencies
tidy:
	go mod tidy

# Full golangci-lint bar (see .golangci.yml).
lint:
	$(GOLANGCI_LINT) run ./...

# Auto-fix what golangci-lint can fix (wsl_v5 whitespace; review diff).
lint-fix:
	$(GOLANGCI_LINT) run --fix ./...

# Delta vs pinned lint baseline; does not require full baseline clean.
# 81fb0ce is this branch's merge-base with master; pinning it keeps lint-new
# deterministic as master advances.
LINT_BASE_REF ?= 81fb0ce
lint-new:
	$(GOLANGCI_LINT) run --new-from-rev=$(LINT_BASE_REF) ./...

# Shellcheck: lint all tracked shell scripts (parity with pre-commit shellcheck hook).
# Null-safe via IFS= read -r; "--" guards leading-hyphen paths; set -e fails closed.
.PHONY: shellcheck
shellcheck:
	@set -eu; \
	files=$$(git ls-files '*.sh'); \
	if [ -z "$$files" ]; then \
		echo "no tracked shell scripts to lint"; \
	else \
		printf '%s\n' "$$files" | while IFS= read -r f; do shellcheck -- "$$f"; done; \
	fi

# actionlint: lint GitHub workflow files (parity with pre-commit actionlint hook).
# Bare invocation lints .github/workflows/*.yml, matching the CI actionlint job.
.PHONY: actionlint
actionlint:
	@command -v $(ACTIONLINT) >/dev/null 2>&1 || (echo "actionlint not found; install with: make tools"; exit 1)
	$(ACTIONLINT)

# Security checks are strict locally and blocking in CI.
security:
	$(GOVULNCHECK) ./...
	$(GOLANGCI_LINT) run --enable-only=gosec ./...

# Print transitive license tree for the server binary (go-licenses report).
licenses:
	@command -v $(GO_LICENSES) >/dev/null 2>&1 || (echo "go-licenses not found; install with: make tools"; exit 1)
	$(GO_LICENSES) report $(GO_LICENSES_PKG)

# License allowlist check. Strict locally and blocking in CI.
licenses-check:
	@command -v $(GO_LICENSES) >/dev/null 2>&1 || (echo "go-licenses not found; install with: make tools"; exit 1)
	$(GO_LICENSES) check $(GO_LICENSES_PKG) --allowed_licenses=$(ALLOWED_LICENSES)

# Save third-party NOTICE/LICENSE files for the licenses-notices CI artifact.
licenses-save:
	@command -v $(GO_LICENSES) >/dev/null 2>&1 || (echo "go-licenses not found; install with: make tools"; exit 1)
	$(GO_LICENSES) save $(GO_LICENSES_PKG) \
		--ignore=$(GO_LICENSES_IGNORE) \
		--save_path=$(LICENSES_SAVE_PATH) \
		--force

# markdownlint-cli2 via bunx (pinned MARKDOWNLINT_CLI2_VERSION). Uses .markdownlint.json.
# Strict locally and blocking in CI.
markdownlint:
	@command -v bun >/dev/null 2>&1 || (echo "bun not found; install from https://bun.sh"; exit 1)
	$(MARKDOWNLINT) "**/*.md" "#node_modules" "#**/node_modules/**"

markdownlint-fix:
	@command -v bun >/dev/null 2>&1 || (echo "bun not found; install from https://bun.sh"; exit 1)
	$(MARKDOWNLINT) --fix "**/*.md" "#node_modules" "#**/node_modules/**"

# typos binary (Rust; not go-installable). Config: .typos.toml.
# Strict locally and blocking in CI.
typos:
	@command -v $(TYPOS) >/dev/null 2>&1 || (echo "typos not found; install $(TYPOS_VERSION) from https://github.com/crate-ci/typos/releases"; exit 1)
	$(TYPOS) --config .typos.toml

# hadolint binary (Haskell; not go-installable). Does not modify docker/Dockerfile.
# Strict locally and blocking in CI.
hadolint:
	@command -v $(HADOLINT) >/dev/null 2>&1 || (echo "hadolint not found; install $(HADOLINT_VERSION) from https://github.com/hadolint/hadolint/releases"; exit 1)
	$(HADOLINT) $(HADOLINT_FLAGS) docker/Dockerfile

# yamllint via uvx (pinned YAMLLINT_VERSION). Explicit non-workflow paths only.
# Strict locally and blocking in CI.
yamllint:
	@command -v uvx >/dev/null 2>&1 || (echo "uv/uvx not found; install from https://docs.astral.sh/uv/"; exit 1)
	$(YAMLLINT) -c .yamllint $(YAMLLINT_PATHS)

# Light local check: no full lint, no security scan.
check: fmt-check vet lint-new test-go

# Install pre-commit.com git hooks (.pre-commit-config.yaml).
# Staged: gofmt/goimports. Index snapshot (full module): go-vet.
# Full module: golangci-lint (make lint), go-test-unit (make test-go),
# reuse (make reuse-lint), go-mod-tidy (CI tidy).
pre-commit-install:
	uv run pre-commit install

# Run pre-commit hooks (same as git commit). Mirrors the CI check set where
# hooks are wired; see CONTRIBUTING.md for conditional parity notes.
pre-commit-run:
	uv run pre-commit run

# Laptop CI mirror: fmt, vet, lint, shellcheck, actionlint, security,
# licenses, hygiene quartet, unit+integration, build, pins, reuse.
# License and hygiene targets are strict locally and blocking in CI.
ci: fmt-check vet lint shellcheck actionlint security licenses licenses-check \
	markdownlint typos hadolint yamllint \
	test build verify-action-pins reuse-lint

# List immutable action@sha references found in workflow files (audit helper).
generate-action-inventory:
	nu .github/scripts/generate-action-inventory.nu

# Fail on mutable tags or SHAs that diverge from .github/action-pins.yml.
verify-action-pins:
	nu .github/scripts/verify-action-pins.nu

# REUSE licensing compliance; reuse comes from the uv dev group.
reuse-lint:
	uv run reuse lint
