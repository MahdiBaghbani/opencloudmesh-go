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

	if !pathMatchesRoute("/validator/api/session/run-1", "/validator/api/session/{id}", true) {
		t.Fatal("expected session id path to match with MatchExact")
	}

	if pathMatchesRoute("/validator/api/session/run-1/extra", "/validator/api/session/{id}", true) {
		t.Fatal("expected session suffix path to not match with MatchExact")
	}

	if pathMatchesRoute("/validator/api/session", "/validator/api/session/{id}", true) {
		t.Fatal("expected session prefix without id to not match with MatchExact")
	}

	if !pathMatchesRoute("/validator/api/report/run-1/retention", "/validator/api/report/{id}/retention", true) {
		t.Fatal("expected retention path to match with MatchExact")
	}

	if pathMatchesRoute("/validator/api/report/run-1/retention/extra", "/validator/api/report/{id}/retention", true) {
		t.Fatal("expected retention suffix path to not match with MatchExact")
	}

	if !pathMatchesRoute("/validator/api/report/run-1/lock", "/validator/api/report/{id}/lock", true) {
		t.Fatal("expected lock path to match with MatchExact")
	}

	if pathMatchesRoute("/validator/api/report/run-1/lock/extra", "/validator/api/report/{id}/lock", true) {
		t.Fatal("expected lock suffix path to not match with MatchExact")
	}

	if pathMatchesRoute("/validator/report/run-1/", "/validator/report/{id}", true) {
		t.Fatal("expected HTML trailing slash not to match with MatchExact")
	}

	if pathMatchesRoute("/validator/api/report/run-1/", "/validator/api/report/{id}", true) {
		t.Fatal("expected JSON trailing slash not to match with MatchExact")
	}

	if !pathMatchesRoute("/validator/report/run-1", "/validator/report/{id}", true) {
		t.Fatal("expected HTML report path to match with MatchExact")
	}

	if !pathMatchesRoute("/validator/api/report/run-1", "/validator/api/report/{id}", true) {
		t.Fatal("expected JSON report path to match with MatchExact")
	}

	if pathMatchesRoute("//validator/api/report/run-1", "/validator/api/report/{id}", true) {
		t.Fatal("expected double-leading-slash report path not to match with MatchExact")
	}
}

func TestPathMatchesRoute_MatchExactSessionInvite(t *testing.T) {
	t.Parallel()

	if !pathMatchesRoute("/validator/api/session/run-1/invite", "/validator/api/session/{id}/invite", true) {
		t.Fatal("expected session invite claim path to match with MatchExact")
	}

	if pathMatchesRoute("/validator/api/session/run-1/invite/extra", "/validator/api/session/{id}/invite", true) {
		t.Fatal("expected session invite suffix path to not match with MatchExact")
	}

	if pathMatchesRoute("/validator/api/session/run-1", "/validator/api/session/{id}/invite", true) {
		t.Fatal("expected session poll path to not match invite claim pattern")
	}
}

func TestPathMatchesRoute_MatchExactSessionAbort(t *testing.T) {
	t.Parallel()

	if !pathMatchesRoute("/validator/api/session/run-1/abort", "/validator/api/session/{id}/abort", true) {
		t.Fatal("expected session abort path to match with MatchExact")
	}

	if pathMatchesRoute("/validator/api/session/run-1/abort/extra", "/validator/api/session/{id}/abort", true) {
		t.Fatal("expected session abort suffix path to not match with MatchExact")
	}

	if pathMatchesRoute("/validator/api/session/run-1", "/validator/api/session/{id}/abort", true) {
		t.Fatal("expected session poll path to not match abort pattern")
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
