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
			name:     "webdav requires auth (no base path)",
			path:     "/webdav/ocm/somefile",
			basePath: "",
			want:     true,
		},
		{
			name:     "webdav requires auth (with base path)",
			path:     "/ocm/webdav/ocm/somefile",
			basePath: "/ocm",
			want:     true,
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
