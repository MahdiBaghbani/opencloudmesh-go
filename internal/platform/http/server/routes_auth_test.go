package server

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/routing"
)

func TestIsAuthRequired_FromRoutePolicyAggregate(t *testing.T) {
	opts := service.DefaultRouteOpts()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "well-known-ocm is public", path: "/.well-known/ocm", want: false},
		{name: "ocm-provider is public", path: "/ocm-provider", want: false},
		{name: "healthz is public", path: "/api/healthz", want: false},
		{name: "auth/login is public", path: "/api/auth/login", want: false},
		{name: "ui/login is public", path: "/ui/login", want: false},
		{name: "ui/static requires auth", path: "/ui/static/main.css", want: true},
		{name: "ocm/shares is public", path: "/ocm/shares", want: false},
		{name: "ocm-aux is public", path: "/ocm-aux/discover", want: false},
		{name: "api/users requires auth", path: "/api/users", want: true},
		{name: "api/inbox requires auth", path: "/api/inbox/shares", want: true},
		{name: "ui/dashboard requires auth", path: "/ui/dashboard", want: true},
		{name: "webdav bearer not session", path: "/webdav/ocm/somefile", want: false},
		{name: "unknown path requires auth", path: "/unknown/path", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAuthRequired(tt.path, opts)
			if got != tt.want {
				t.Errorf("IsAuthRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsAuthRequired_WithExternalBasePath(t *testing.T) {
	opts := service.RouteOpts{
		ExternalBasePath:    "/ocm",
		WayfEnabled:         false,
		InviteAcceptEnabled: false,
		TokenExchangePath:   "token",
	}

	cases := []struct {
		path string
		want bool
	}{
		{"/ocm/api/healthz", false},
		{"/ocm/webdav/ocm/somefile", false},
		{"/ocm/api/inbox/shares", true},
	}
	for _, tc := range cases {
		got := IsAuthRequired(tc.path, opts)
		if got != tc.want {
			t.Errorf("IsAuthRequired(%q, base=/ocm) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestIsAuthRequired_WayfEnabled(t *testing.T) {
	opts := service.RouteOpts{
		WayfEnabled:         true,
		InviteAcceptEnabled: true,
		TokenExchangePath:   "token",
	}
	if IsAuthRequired("/ui/wayf", opts) {
		t.Error("expected /ui/wayf public when WAYF enabled")
	}
	if !IsAuthRequired("/ui/accept-invite", opts) {
		t.Error("expected /ui/accept-invite protected when invite accept enabled")
	}
}
