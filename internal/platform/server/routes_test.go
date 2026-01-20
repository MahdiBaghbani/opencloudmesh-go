package server

import (
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

// mockService is a minimal Service implementation for testing.
type mockService struct {
	prefix      string
	unprotected []string
}

func (m *mockService) Handler() http.Handler           { return nil }
func (m *mockService) Prefix() string                  { return m.prefix }
func (m *mockService) Unprotected() []string           { return m.unprotected }
func (m *mockService) Close() error                    { return nil }

// testServices returns a slice of mock services matching the actual service declarations.
func testServices() []service.Service {
	return []service.Service{
		// wellknown service (root-mounted, no prefix)
		&mockService{prefix: "", unprotected: []string{"/.well-known/ocm", "/ocm-provider"}},
		// ocm service (public via routeGroups)
		&mockService{prefix: "ocm", unprotected: []string{"/shares", "/notifications", "/invite-accepted", "/token"}},
		// ocmaux service
		&mockService{prefix: "ocm-aux", unprotected: []string{"/federations", "/discover"}},
		// apiservice
		&mockService{prefix: "api", unprotected: []string{"/healthz", "/auth/login"}},
		// uiservice
		&mockService{prefix: "ui", unprotected: []string{"/login", "/static"}},
		// webdavservice (uses bearer/basic, not session)
		&mockService{prefix: "webdav", unprotected: []string{"/ocm"}},
	}
}

func TestRouteGroups(t *testing.T) {
	groups := GetRouteGroups()

	if len(groups) == 0 {
		t.Fatal("expected at least one route group")
	}

	// Verify root-only endpoints exist
	foundWellKnown := false
	foundOcmProvider := false
	for _, rg := range groups {
		if rg.PathPrefix == "/.well-known/ocm" && rg.AtHostRoot {
			foundWellKnown = true
		}
		if rg.PathPrefix == "/ocm-provider" && rg.AtHostRoot {
			foundOcmProvider = true
		}
	}

	if !foundWellKnown {
		t.Error("expected /.well-known/ocm to be a root-only endpoint")
	}
	if !foundOcmProvider {
		t.Error("expected /ocm-provider to be a root-only endpoint")
	}
}

func TestIsAuthRequired(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		basePath string
		want     bool
	}{
		// Root-only public endpoints
		{
			name:     "well-known-ocm is public",
			path:     "/.well-known/ocm",
			basePath: "",
			want:     false,
		},
		{
			name:     "ocm-provider is public",
			path:     "/ocm-provider",
			basePath: "",
			want:     false,
		},

		// Public exceptions
		{
			name:     "healthz is public (no base path)",
			path:     "/api/healthz",
			basePath: "",
			want:     false,
		},
		{
			name:     "healthz is public (with base path)",
			path:     "/ocm/api/healthz",
			basePath: "/ocm",
			want:     false,
		},
		{
			name:     "auth/login is public",
			path:     "/api/auth/login",
			basePath: "",
			want:     false,
		},
		{
			name:     "ui/login is public",
			path:     "/ui/login",
			basePath: "",
			want:     false,
		},
		{
			name:     "ui/static is public",
			path:     "/ui/static/main.css",
			basePath: "",
			want:     false,
		},

		// OCM endpoints are public (federation)
		{
			name:     "ocm/shares is public",
			path:     "/ocm/shares",
			basePath: "",
			want:     false,
		},
		{
			name:     "ocm-aux is public",
			path:     "/ocm-aux/discover",
			basePath: "",
			want:     false,
		},

		// Protected endpoints
		{
			name:     "api/users requires auth",
			path:     "/api/users",
			basePath: "",
			want:     true,
		},
		{
			name:     "api/inbox requires auth",
			path:     "/api/inbox/shares",
			basePath: "",
			want:     true,
		},
		{
			name:     "ui/dashboard requires auth",
			path:     "/ui/dashboard",
			basePath: "",
			want:     true,
		},
		// WebDAV uses bearer/basic auth, not session auth
		{
			name:     "webdav uses bearer auth not session (no base path)",
			path:     "/webdav/ocm/somefile",
			basePath: "",
			want:     false,
		},
		{
			name:     "webdav uses bearer auth not session (with base path)",
			path:     "/ocm/webdav/ocm/somefile",
			basePath: "/ocm",
			want:     false,
		},
		{
			name:     "unknown path requires auth",
			path:     "/unknown/path",
			basePath: "",
			want:     true,
		},
	}

	// Create mock services for testing
	svcs := testServices()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAuthRequired(tt.path, tt.basePath, svcs)
			if got != tt.want {
				t.Errorf("IsAuthRequired(%q, %q, svcs) = %v, want %v", tt.path, tt.basePath, got, tt.want)
			}
		})
	}
}

func TestPathMatchesPrefix(t *testing.T) {
	tests := []struct {
		path   string
		prefix string
		want   bool
	}{
		{"/api/healthz", "/api/healthz", true},
		{"/api/healthz/", "/api/healthz", true},
		{"/api/healthz/extra", "/api/healthz", true},
		{"/api/health", "/api/healthz", false},
		{"/api", "/api", true},
		{"/api/", "/api", true},
		{"/apiextra", "/api", false}, // not a subpath
	}

	for _, tt := range tests {
		t.Run(tt.path+"_"+tt.prefix, func(t *testing.T) {
			got := pathMatchesPrefix(tt.path, tt.prefix)
			if got != tt.want {
				t.Errorf("pathMatchesPrefix(%q, %q) = %v, want %v", tt.path, tt.prefix, got, tt.want)
			}
		})
	}
}
