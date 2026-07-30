# OpenCloudMesh server build and test targets.
SHELL := /bin/bash
.PHONY: build test-go test-integration test-e2e test-e2e-install \
	test clean fmt fmt-check vet tidy tools lint lint-fix lint-new security check ci \
	generate-action-inventory verify-action-pins

# Build the server binary
build:
	go build -o bin/opencloudmesh-go ./cmd/opencloudmesh-go

# Run unit tests with race detector (excludes integration tests)
test-go:
	go test -race -coverprofile=coverage-unit.out $$(go list ./... | grep -v /tests/integration)

# Run integration tests only
test-integration:
	go test -race -coverprofile=coverage-integration.out ./tests/integration/...

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
	rm -f coverage-unit.out coverage-integration.out

# --- Static analysis and security (requires: make tools) ---

GOLANGCI_LINT_VERSION ?= v2.12.2
GOVULNCHECK_VERSION ?= v1.1.4
GOIMPORTS_VERSION ?= v0.30.0

GOLANGCI_LINT ?= golangci-lint
GOVULNCHECK ?= govulncheck
GOIMPORTS ?= goimports

# Install pinned CLIs into GOBIN (no @latest). gosec runs via golangci-lint
# SSOT only; no standalone gosec binary.
tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)

# Mutating format: go fmt + goimports (matches pre-commit hook).
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

# govulncheck is report-only (mirrors CI continue-on-error); gosec blocks.
security:
	-$(GOVULNCHECK) ./...
	$(GOLANGCI_LINT) run --enable-only=gosec ./...

# Light local check: no full lint, no security scan.
check: fmt-check vet lint-new test-go

# Laptop CI mirror: fmt, vet, lint, security, unit+integration, build, pins.
ci: fmt-check vet lint security test build verify-action-pins

# List immutable action@sha references found in workflow files (audit helper).
generate-action-inventory:
	nu .github/scripts/generate-action-inventory.nu

# Fail on mutable tags or SHAs that diverge from .github/action-pins.yml.
verify-action-pins:
	nu .github/scripts/verify-action-pins.nu
