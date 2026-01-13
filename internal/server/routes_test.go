package server

import (
	"testing"
)

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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAuthRequired(tt.path, tt.basePath)
			if got != tt.want {
				t.Errorf("IsAuthRequired(%q, %q) = %v, want %v", tt.path, tt.basePath, got, tt.want)
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
