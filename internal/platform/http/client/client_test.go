package client_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	outboundtestutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestClient_DoPreservesInterface(t *testing.T) {
	// Verify Do() still works with the standard http.Request interface
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := outboundtestutil.NewPermissive(nil)

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test response body close

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}
