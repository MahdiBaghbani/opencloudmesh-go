package wellknown

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func TestOCMHandler_ServeHTTP(t *testing.T) {
	c := &resolve.ProviderConfig{
		Provider: "TestProvider",
	}

	h := newOCMHandler(
		c,
		nil,
		handlerResolveInputs(t, ""),
		testLogger(),
	)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}

	var disc spec.Discovery
	if err := json.NewDecoder(w.Body).Decode(&disc); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !disc.Enabled {
		t.Error("expected Enabled=true in response")
	}

	if disc.Provider != "TestProvider" {
		t.Errorf("expected Provider 'TestProvider', got %q", disc.Provider)
	}

	if disc.TokenEndPoint == "" {
		t.Error("expected non-empty tokenEndPoint")
	}
}

func TestOCMHandler_ServeHTTP_DisabledDiscovery(t *testing.T) {
	c := &resolve.ProviderConfig{}

	h := newOCMHandler(c, nil, resolve.ResolveInputs{}, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var disc spec.Discovery
	if err := json.NewDecoder(w.Body).Decode(&disc); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if disc.Enabled {
		t.Error("expected Enabled=false in response")
	}
}
