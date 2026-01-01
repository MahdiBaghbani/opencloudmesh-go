.PHONY: build test-go test-integration clean

# Build the server binary
build:
	go build -o bin/opencloudmesh-go ./cmd/opencloudmesh-go

# Run unit tests (excludes integration tests)
test-go:
	go test -race $$(go list ./... | grep -v /tests/integration)

# Run integration tests only
test-integration:
	go test -race ./tests/integration/...

# Run all tests
test: test-go test-integration

# Clean build artifacts
clean:
	rm -rf bin/

# Format code
fmt:
	go fmt ./...

# Vet code
vet:
	go vet ./...

# Tidy dependencies
tidy:
	go mod tidy
