// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validator

import (
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func TestRouteSpecs_ReportPublicAndMatchExact(t *testing.T) {
	t.Parallel()

	enabled := service.RouteOpts{
		ValidatorEnabled:  true,
		TokenExchangePath: "token",
	}

	cases := []struct {
		id      string
		pattern string
		method  string
		surface service.SurfaceClass
		public  string
		extra   string
	}{
		{
			id:      service.RouteIDValidatorAPIReport,
			pattern: RouteAPIReport,
			method:  http.MethodGet,
			surface: service.SurfaceAPI,
			public:  "/validator/api/report/run-1",
			extra:   "/validator/api/report/run-1/extra",
		},
		{
			id:      service.RouteIDValidatorHTMLReport,
			pattern: RouteHTMLReport,
			method:  http.MethodGet,
			surface: service.SurfaceUI,
			public:  "/validator/report/run-1",
			extra:   "/validator/report/run-1/extra",
		},
		{
			id:      service.RouteIDValidatorAPIReportRetention,
			pattern: RouteAPIReportRetention,
			method:  http.MethodPatch,
			surface: service.SurfaceAPI,
			public:  "/validator/api/report/run-1/retention",
			extra:   "/validator/api/report/run-1/retention/extra",
		},
		{
			id:      service.RouteIDValidatorAPIReportLock,
			pattern: RouteAPIReportLock,
			method:  http.MethodPost,
			surface: service.SurfaceAPI,
			public:  "/validator/api/report/run-1/lock",
			extra:   "/validator/api/report/run-1/lock/extra",
		},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			t.Parallel()

			spec := findValidatorSpec(t, enabled, tc.pattern)
			if spec.ID != tc.id {
				t.Fatalf("ID = %q, want %q", spec.ID, tc.id)
			}

			if spec.Method != tc.method {
				t.Fatalf("Method = %q, want %q", spec.Method, tc.method)
			}

			if spec.SessionPolicy != service.SessionPublic {
				t.Fatalf("SessionPolicy = %q, want public", spec.SessionPolicy)
			}

			if spec.HandlerAuth != service.HandlerAuthNone {
				t.Fatalf("HandlerAuth = %q, want none", spec.HandlerAuth)
			}

			if spec.SurfaceClass != tc.surface {
				t.Fatalf("SurfaceClass = %q, want %q", spec.SurfaceClass, tc.surface)
			}

			if spec.FeatureCondition != service.FeatureValidatorEnabled {
				t.Fatalf("FeatureCondition = %q", spec.FeatureCondition)
			}

			row := findEnabledRow(t, enabled, tc.id)
			if !row.MatchExact {
				t.Fatal("expected MatchExact true")
			}

			if service.SessionAuthRequiredForPath(tc.public, enabled) {
				t.Fatalf("expected anonymous access to %q", tc.public)
			}

			if !service.SessionAuthRequiredForPath(tc.extra, enabled) {
				t.Fatalf("expected %q protected via MatchExact", tc.extra)
			}
		})
	}
}

func findValidatorSpec(t *testing.T, opts service.RouteOpts, pattern string) service.RouteSpec {
	t.Helper()

	for _, spec := range service.RegisteredRouteSpecs(opts) {
		if spec.Service == string(service.BuildValidator) && spec.Pattern == pattern {
			return spec
		}
	}

	t.Fatalf("expected validator spec for %q", pattern)

	return service.RouteSpec{}
}

func findEnabledRow(t *testing.T, opts service.RouteOpts, id string) service.RouteRow {
	t.Helper()

	for _, row := range service.Routes(opts) {
		if row.ID == id {
			return row
		}
	}

	t.Fatalf("expected route row %q", id)

	return service.RouteRow{}
}
