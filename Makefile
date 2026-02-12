# OpenCloudMesh server build and test targets.
.PHONY: build test-go test-integration test-e2e test clean fmt vet tidy

# Build the server binary
build:
	go build -o bin/opencloudmesh-go ./cmd/opencloudmesh-go

# Run unit tests (excludes integration tests)
test-go:
	go test -race $$(go list ./... | grep -v /tests/integration)

# Run integration tests only
test-integration:
	go test -race ./tests/integration/...

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

# Format code
fmt:
	go fmt ./...

# Vet code
vet:
	go vet ./...

# Tidy dependencies
tidy:
	go mod tidy
