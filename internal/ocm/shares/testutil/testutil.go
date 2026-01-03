// Package testutil provides test helpers for the shares package.
package testutil

import (
	"context"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/discovery"
)

// MockDiscoveryClient is a test helper that wraps discovery functionality.
type MockDiscoveryClient struct {
	baseURL string
}

// NewMockDiscoveryClient creates a mock discovery client.
func NewMockDiscoveryClient(baseURL string) *discovery.Client {
	// Create a real discovery client - in tests, the baseURL points to a mock server
	return discovery.NewClient(nil, nil)
}

// MockHTTPClient wraps an http.Client for testing.
type MockHTTPClient struct {
	client *http.Client
}

// NewMockHTTPClient creates a mock HTTP client.
func NewMockHTTPClient(client *http.Client) *MockHTTPClient {
	return &MockHTTPClient{client: client}
}

// Do executes an HTTP request.
func (c *MockHTTPClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

// GetJSON fetches JSON from a URL.
func (c *MockHTTPClient) GetJSON(ctx context.Context, url string) ([]byte, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	return nil, resp, nil
}
