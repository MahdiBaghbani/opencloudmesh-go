package ui_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ui"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

func TestWayf_UsesPublishedProviderDomain(t *testing.T) {
	id, err := localidentity.Derive("https://cloud.example.com:9200", "")
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if id.ProviderDomain != "cloud.example.com:9200" {
		t.Fatalf("ProviderDomain = %q, want cloud.example.com:9200", id.ProviderDomain)
	}

	handler, err := ui.NewHandler(id.ExternalBasePath, true, id.ProviderDomain)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/wayf?token=abc", nil)
	w := httptest.NewRecorder()
	handler.Wayf(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if body := w.Body.String(); !containsAll(body, id.ProviderDomain) {
		t.Errorf("expected provider domain %q in WAYF page", id.ProviderDomain)
	}
}

func TestNewHandler_UsesValidatedExternalBasePath(t *testing.T) {
	id, err := localidentity.Derive("https://cloud.example.com", "/ocm")
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	handler, err := ui.NewHandler(id.ExternalBasePath, false, id.ProviderDomain)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	handler.Login(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if body := w.Body.String(); !containsAll(body, "/ocm") {
		t.Error("expected validated base path in login page")
	}
}

func containsAll(body, substr string) bool {
	return len(substr) == 0 || (len(body) >= len(substr) && indexOf(body, substr) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
