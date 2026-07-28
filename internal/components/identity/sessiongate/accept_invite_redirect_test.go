package sessiongate

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestAuthGate_AcceptInviteRedirectPreservesFullQuery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError}))

	protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := chi.NewRouter()
	r.Use(NewAuthGate(AuthGateConfig{
		RequireAuth: func(path string) bool {
			return path == "/ui/accept-invite"
		},
		Log:         logger,
		SessionRepo: &testSessionRepo{},
		PartyRepo:   newTestPartyRepo(),
	}))
	r.Get("/ui/accept-invite", protected)

	originalQuery := "token=invite-abc&providerDomain=alice.example.com"
	req := httptest.NewRequest(http.MethodGet, "/ui/accept-invite?"+originalQuery, nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header")
	}

	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}

	if parsed.Path != "/ui/login" {
		t.Fatalf("expected login path /ui/login, got %q", parsed.Path)
	}

	redirect := parsed.Query().Get("redirect")

	wantRedirect := "/ui/accept-invite?" + originalQuery
	if redirect != wantRedirect {
		t.Fatalf("redirect = %q, want %q", redirect, wantRedirect)
	}
}

func TestAuthGate_AcceptInviteRedirectPreservesQueryWithBasePath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError}))

	protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := chi.NewRouter()
	r.Use(NewAuthGate(AuthGateConfig{
		RequireAuth: func(path string) bool {
			return path == "/ocm/ui/accept-invite"
		},
		Log:         logger,
		SessionRepo: &testSessionRepo{},
		PartyRepo:   newTestPartyRepo(),
		BasePath:    "/ocm",
	}))
	r.Get("/ocm/ui/accept-invite", protected)

	originalQuery := "token=xyz&providerDomain=bob.example.com"
	req := httptest.NewRequest(http.MethodGet, "/ocm/ui/accept-invite?"+originalQuery, nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rr.Code)
	}

	parsed, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}

	if parsed.Path != "/ocm/ui/login" {
		t.Fatalf("expected login path /ocm/ui/login, got %q", parsed.Path)
	}

	redirect := parsed.Query().Get("redirect")

	wantRedirect := "/ocm/ui/accept-invite?" + originalQuery
	if redirect != wantRedirect {
		t.Fatalf("redirect = %q, want %q", redirect, wantRedirect)
	}
}
