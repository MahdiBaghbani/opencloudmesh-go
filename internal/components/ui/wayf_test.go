package ui_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ui"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

func TestWayf_UsesPublishedProviderDomainStrippedDefaultPort(t *testing.T) {
	id, err := localidentity.Derive("https://cloud.example.com:443", "")
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if id.ProviderDomain != "cloud.example.com" {
		t.Fatalf("ProviderDomain = %q, want cloud.example.com (default port stripped)", id.ProviderDomain)
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

	body := w.Body.String()
	if !strings.Contains(body, `const providerDomain = "cloud.example.com"`) {
		t.Errorf("expected stripped provider domain in WAYF page, got body snippet around providerDomain")
	}
	if strings.Contains(body, "cloud.example.com:443") {
		t.Error("expected default port stripped from providerDomain in WAYF page")
	}
}

func TestWayf_ReadsTokenFromQuery(t *testing.T) {
	handler, err := ui.NewHandler("", true, "alice.example.com")
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/wayf?token=invite-token-123", nil)
	w := httptest.NewRecorder()
	handler.Wayf(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, `const token = "invite-token-123"`) {
		t.Error("expected token from query embedded in WAYF page")
	}
}

func TestWayf_NonDefaultPortPreservedInProviderDomain(t *testing.T) {
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

	body := w.Body.String()
	if !strings.Contains(body, `const providerDomain = "cloud.example.com:9200"`) {
		t.Error("expected non-default port preserved in WAYF providerDomain")
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
	if body := w.Body.String(); !strings.Contains(body, "/ocm") {
		t.Error("expected validated base path in login page")
	}
}
