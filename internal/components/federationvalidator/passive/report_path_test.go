// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestJoinReportPath_ExternalBaseVariants(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		base string
		want string
	}{
		{name: "empty", base: "", want: "/validator/report/{id}"},
		{name: "slash only", base: "/", want: "/validator/report/{id}"},
		{name: "slash padded empty", base: "///", want: "/validator/report/{id}"},
		{name: "non-empty", base: "ocm", want: "/ocm/validator/report/{id}"},
		{name: "slash padded", base: "/ocm/", want: "/ocm/validator/report/{id}"},
		{name: "nested", base: "/app/ocm/", want: "/app/ocm/validator/report/{id}"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := joinReportPath(tc.base, manifestServicePrefix, RouteHTMLReport)
			if got != tc.want {
				t.Fatalf("joinReportPath(%q) = %q, want %q", tc.base, got, tc.want)
			}
		})
	}
}

func TestBuildManifest_ExternalBasePathJoinConsistency(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		base string
	}{
		{name: "empty", base: ""},
		{name: "slash padded empty", base: "///"},
		{name: "slash padded", base: "/ocm/"},
		{name: "non-empty", base: "ocm"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			payload := buildManifest(tc.base)
			wantHTML := joinReportPath(tc.base, manifestServicePrefix, RouteHTMLReport)
			wantAPI := joinReportPath(tc.base, manifestServicePrefix, RouteAPIReport)
			wantPatch := joinReportPath(tc.base, manifestServicePrefix, RouteAPIReportRetention)
			wantLock := joinReportPath(tc.base, manifestServicePrefix, RouteAPIReportLock)

			if payload.Report.HTMLPath != wantHTML {
				t.Fatalf("htmlPath = %q, want %q", payload.Report.HTMLPath, wantHTML)
			}

			if payload.Report.APIPath != wantAPI {
				t.Fatalf("apiPath = %q, want %q", payload.Report.APIPath, wantAPI)
			}

			if payload.Retention.PatchPath != wantPatch {
				t.Fatalf("patchPath = %q, want %q", payload.Retention.PatchPath, wantPatch)
			}

			if payload.Retention.LockPath != wantLock {
				t.Fatalf("lockPath = %q, want %q", payload.Retention.LockPath, wantLock)
			}

			wantRoutePrefix := joinReportPath(tc.base, manifestServicePrefix) + "/"

			var sawReport bool

			for _, route := range payload.Routes {
				if !strings.HasPrefix(route.FullPath, wantRoutePrefix) {
					t.Fatalf("route %s %s missing shared join prefix %q", route.Method, route.FullPath, wantRoutePrefix)
				}

				if route.Method == http.MethodGet && route.FullPath == wantAPI {
					sawReport = true
				}
			}

			if !sawReport {
				t.Fatalf("routes[] missing GET %s", wantAPI)
			}
		})
	}
}

func TestHandleManifest_SlashPaddedBaseUsesSharedJoin(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)
	h.SetExternalBasePath("/ocm/")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/manifest", nil)
	rec := httptest.NewRecorder()
	h.HandleManifest(rec, req)

	var body manifestRouteResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	wantAPI := joinReportPath("/ocm/", manifestServicePrefix, RouteAPIReport)
	if body.Report.APIPath != wantAPI {
		t.Fatalf("report.apiPath = %q, want %q", body.Report.APIPath, wantAPI)
	}

	if body.Retention.PatchPath != joinReportPath("/ocm/", manifestServicePrefix, RouteAPIReportRetention) {
		t.Fatalf("patchPath = %q", body.Retention.PatchPath)
	}

	for _, route := range body.Routes {
		if !strings.HasPrefix(route.FullPath, "/ocm/validator/") {
			t.Fatalf("route path %q did not use shared join", route.FullPath)
		}
	}
}

func TestHandleReport_TrailingSlashNotServed(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-trailing-slash"
	seedReportRun(t, store, &validatorcore.TestRun{TestRunID: runID})

	router := newReportTestRouter(t, h)
	paths := []string{"/report/" + runID + "/", "/api/report/" + runID + "/"}

	for _, path := range paths {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, rec.Code)
		}
	}
}
