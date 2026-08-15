// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package service

import "testing"

func TestPathMatchesRoute(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		pattern string
		want    bool
	}{
		{
			name:    "exact match",
			path:    "/api/healthz",
			pattern: "/api/healthz",
			want:    true,
		},
		{
			name:    "wildcard child path ocm subtree",
			path:    "/ocm/foo",
			pattern: "/ocm/*",
			want:    true,
		},
		{
			name:    "wildcard child path",
			path:    "/webdav/ocm/foo",
			pattern: "/webdav/ocm/*",
			want:    true,
		},
		{
			name:    "wildcard prefix only",
			path:    "/webdav/ocm",
			pattern: "/webdav/ocm/*",
			want:    true,
		},
		{
			name:    "param segment",
			path:    "/api/inbox/shares/abc",
			pattern: "/api/inbox/shares/{shareId}",
			want:    true,
		},
		{
			name:    "param nested suffix",
			path:    "/api/inbox/shares/abc/accept",
			pattern: "/api/inbox/shares/{shareId}/accept",
			want:    true,
		},
		{
			name:    "prefix must not match longer sibling segment",
			path:    "/apiextra",
			pattern: "/api",
			want:    false,
		},
		{
			name:    "prefix child path",
			path:    "/api/inbox/shares",
			pattern: "/api/inbox/shares",
			want:    true,
		},
		{
			name:    "trailing slash does not extend to sibling prefix",
			path:    "/api/",
			pattern: "/api/inbox/shares",
			want:    false,
		},
		{
			name:    "unrelated path",
			path:    "/other/path",
			pattern: "/api/inbox/shares/{shareId}",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := pathMatchesRoute(tt.path, tt.pattern, false)
			if got != tt.want {
				t.Errorf("pathMatchesRoute(%q, %q) = %v, want %v", tt.path, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestPathMatchesRoute_MatchExact(t *testing.T) {
	t.Parallel()

	if !pathMatchesRoute("/validator/api/statistics", "/validator/api/statistics", true) {
		t.Fatal("expected exact statistics path to match")
	}

	if pathMatchesRoute("/validator/api/statistics/foo", "/validator/api/statistics", true) {
		t.Fatal("expected statistics subpath to not match with MatchExact")
	}
}

func TestSessionAuthChecker_MatchesSessionAuthRequiredForPath(t *testing.T) {
	t.Parallel()

	opts := DefaultRouteOpts()
	checker := NewSessionAuthChecker(opts)

	paths := []string{
		"/.well-known/ocm",
		"/api/healthz",
		"/api/auth/login",
		"/api/inbox/shares",
		"/api/inbox/shares/abc",
		"/webdav/ocm/somefile",
		"/ui/dashboard",
		"/unknown/path",
	}

	for _, path := range paths {
		got := checker.Required(path)

		want := SessionAuthRequiredForPath(path, opts)
		if got != want {
			t.Errorf("checker.Required(%q) = %v, SessionAuthRequiredForPath = %v", path, got, want)
		}
	}
}
