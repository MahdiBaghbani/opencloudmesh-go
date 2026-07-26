package ui_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ui"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"
)

func TestLogin_IncludesSafeRedirectHandling(t *testing.T) {
	id := tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm")

	handler, err := ui.NewHandler(id.ExternalBasePath, id.ProviderDomain)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	handler.Login(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	for _, want := range []string{
		"getSafeRedirect",
		`+ "/ui/"`,
		"redirect",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected login page to include %q for post-login redirect", want)
		}
	}

	if !strings.Contains(body, "/ocm") {
		t.Error("expected base path in login page")
	}
}

func TestLogin_AcceptsRedirectQueryForAcceptInvite(t *testing.T) {
	id := tslocalid.MustTestIdentity(t, "https://cloud.example.com", "")

	handler, err := ui.NewHandler(id.ExternalBasePath, id.ProviderDomain)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	returnPath := "/ui/accept-invite?token=tok&providerDomain=alice.example.com"
	req := httptest.NewRequest(http.MethodGet, "/login?redirect="+returnPath, nil)
	w := httptest.NewRecorder()
	handler.Login(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "window.location.search") {
		t.Error("expected login page to read redirect from query string")
	}
}
