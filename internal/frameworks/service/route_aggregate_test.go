// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package service_test

import (
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/api"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocmaux"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/validator"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/wellknown"
)

func TestRoutes_IsCanonicalAggregate(t *testing.T) {
	t.Parallel()

	opts := service.DefaultRouteOpts()
	inventory := service.DerivedRouteInventory(opts)
	rows := service.Routes(opts)

	productCount := 0

	for _, row := range rows {
		if !row.Synthetic {
			productCount++
		}
	}

	if productCount != len(inventory) {
		t.Fatalf("Routes product count = %d, inventory = %d", productCount, len(inventory))
	}
}

func TestRoutes_ProductRowsHavePolicyMetadata(t *testing.T) {
	t.Parallel()

	opts := service.DefaultRouteOpts()
	for _, row := range service.Routes(opts) {
		if row.Synthetic {
			continue
		}

		if row.SurfaceClass == "" {
			t.Errorf("product route %q missing SurfaceClass", row.ID)
		}

		if row.HandlerAuth == "" {
			t.Errorf("product route %q missing HandlerAuth", row.ID)
		}

		if row.TrustClass == "" {
			t.Errorf("product route %q missing TrustClass", row.ID)
		}
	}
}

func TestRoutes_SyntheticRowsHaveSurfaceClass(t *testing.T) {
	t.Parallel()

	opts := service.DefaultRouteOpts()
	for _, row := range service.Routes(opts) {
		if !row.Synthetic {
			continue
		}

		if row.SurfaceClass == "" {
			t.Errorf("synthetic row %q missing SurfaceClass", row.ID)
		}
	}
}

func TestRoutes_ProtocolRowsUseHTTPSigHandlerAuth(t *testing.T) {
	t.Parallel()

	opts := service.DefaultRouteOpts()
	for _, row := range service.Routes(opts) {
		if row.Synthetic || row.SurfaceClass != service.SurfaceProtocol {
			continue
		}

		if row.HandlerAuth != service.HandlerAuthRequiredHTTPSig {
			t.Errorf("protocol route %q HandlerAuth = %q, want required HTTP signature", row.ID, row.HandlerAuth)
		}
	}
}

func TestRoutes_APIOutboundKindsDeclaredOnAPIRows(t *testing.T) {
	t.Parallel()

	opts := service.DefaultRouteOpts()
	found := map[service.OutboundProtocolKind]bool{
		service.OutboundShares:  false,
		service.OutboundInvites: false,
		service.OutboundAccess:  false,
	}

	for _, row := range service.Routes(opts) {
		if row.Synthetic || row.SurfaceClass != service.SurfaceAPI {
			continue
		}

		if row.OutboundProtocolKind == service.OutboundNone {
			continue
		}

		found[row.OutboundProtocolKind] = true
	}

	for kind, ok := range found {
		if !ok {
			t.Errorf("Routes(opts) missing api row with outbound kind %q", kind)
		}
	}
}

func TestRoutes_ValidatorStatisticsMatchExactOnRouteRow(t *testing.T) {
	t.Parallel()

	opts := validatorEnabledRouteOpts()
	statsRow := findRouteRowByID(t, opts, service.RouteIDValidatorAPIStatistics)

	if !statsRow.MatchExact {
		t.Fatal("expected MatchExact true on RouteRow for statistics")
	}

	if statsRow.FullPath != "/validator/api/statistics" {
		t.Fatalf("FullPath = %q, want /validator/api/statistics", statsRow.FullPath)
	}

	if !service.SessionAuthRequiredForPath("/validator/api/statistics/foo", opts) {
		t.Error("expected /validator/api/statistics/foo protected via RouteRow MatchExact")
	}
}

func TestRoutes_ValidatorSessionMatchExactOnRouteRow(t *testing.T) {
	t.Parallel()

	opts := validatorEnabledRouteOpts()
	sessionRow := findRouteRowByID(t, opts, service.RouteIDValidatorAPISession)

	if !sessionRow.MatchExact {
		t.Fatal("expected MatchExact true on RouteRow for session")
	}

	if sessionRow.FullPath != "/validator/api/session/{id}" {
		t.Fatalf("FullPath = %q, want /validator/api/session/{id}", sessionRow.FullPath)
	}

	if !service.SessionAuthRequiredForPath("/validator/api/session/run-1/extra", opts) {
		t.Error("expected /validator/api/session/run-1/extra protected via RouteRow MatchExact")
	}

	if service.SessionAuthRequiredForPath("/validator/api/session/run-1", opts) {
		t.Error("expected /validator/api/session/run-1 public")
	}
}

func TestRoutes_ReportTrailingSlashDoesNotInheritPublicExact(t *testing.T) {
	t.Parallel()

	opts := validatorEnabledRouteOpts()

	if service.SessionAuthRequiredForPath("/validator/report/run-1", opts) {
		t.Error("expected /validator/report/run-1 public")
	}

	if service.SessionAuthRequiredForPath("/validator/api/report/run-1", opts) {
		t.Error("expected /validator/api/report/run-1 public")
	}

	if !service.SessionAuthRequiredForPath("/validator/report/run-1/", opts) {
		t.Error("expected HTML trailing slash not to inherit public exact match")
	}

	if !service.SessionAuthRequiredForPath("/validator/api/report/run-1/", opts) {
		t.Error("expected JSON trailing slash not to inherit public exact match")
	}

	if !service.SessionAuthRequiredForPath("//validator/api/report/run-1", opts) {
		t.Error("expected double-leading-slash JSON report path to fall to protected subtree")
	}

	if !service.SessionAuthRequiredForPath("//validator/report/run-1", opts) {
		t.Error("expected double-leading-slash HTML report path to fall to protected subtree")
	}
}

func TestRoutes_MatchExactRowsLimitedToValidatorAPIPollRoutes(t *testing.T) {
	t.Parallel()

	opts := validatorEnabledRouteOpts()
	wantExact := map[string]struct{}{
		service.RouteIDValidatorAPIStatistics:      {},
		service.RouteIDValidatorAPISession:         {},
		service.RouteIDValidatorAPIReport:          {},
		service.RouteIDValidatorHTMLReport:         {},
		service.RouteIDValidatorAPIReportRetention: {},
		service.RouteIDValidatorAPIReportLock:      {},
	}
	matchExactCount := 0

	for _, row := range service.Routes(opts) {
		if !row.MatchExact {
			continue
		}

		matchExactCount++

		if _, ok := wantExact[row.ID]; !ok {
			t.Errorf("unexpected MatchExact row %q", row.ID)
		}
	}

	if matchExactCount != len(wantExact) {
		t.Fatalf("MatchExact row count = %d, want %d", matchExactCount, len(wantExact))
	}
}

func validatorEnabledRouteOpts() service.RouteOpts {
	opts := service.DefaultRouteOpts()
	opts.ValidatorEnabled = true

	return opts
}

func findRouteRowByID(t *testing.T, opts service.RouteOpts, id string) service.RouteRow {
	t.Helper()

	for _, row := range service.Routes(opts) {
		if row.ID == id {
			return row
		}
	}

	t.Fatalf("expected route row %q", id)

	return service.RouteRow{}
}

func TestRoutes_ValidatorAPIRoutesGatedByFeature(t *testing.T) {
	t.Parallel()

	expectedPaths := []string{
		"/validator/api/scan",
		"/validator/api/session/{id}",
		"/validator/api/report/{id}",
		"/validator/report/{id}",
		"/validator/api/manifest",
		"/validator/api/statistics",
	}

	enabledOpts := service.DefaultRouteOpts()
	enabledOpts.ValidatorEnabled = true

	enabledByPath := productRouteRowsByPath(t, service.Routes(enabledOpts))

	for _, path := range expectedPaths {
		row, ok := enabledByPath[path]
		if !ok {
			t.Errorf("enabled: expected path %q mounted as product route row", path)

			continue
		}

		if row.Method != http.MethodGet {
			t.Errorf("enabled: path %q Method = %q, want GET", path, row.Method)
		}
	}

	disabledOpts := service.DefaultRouteOpts()
	disabledByPath := productRouteRowsByPath(t, service.Routes(disabledOpts))

	for _, path := range expectedPaths {
		if _, ok := disabledByPath[path]; ok {
			t.Errorf("disabled: path %q must not be mounted", path)
		}
	}

	for _, path := range []string{
		"/validator/api/report/{id}/retention",
		"/validator/api/report/{id}/lock",
	} {
		if _, ok := enabledByPath[path]; !ok {
			t.Errorf("enabled: expected path %q mounted as product route row", path)
		}

		if _, ok := disabledByPath[path]; ok {
			t.Errorf("disabled: path %q must not be mounted", path)
		}
	}
}

func productRouteRowsByPath(t *testing.T, rows []service.RouteRow) map[string]service.RouteRow {
	t.Helper()

	byPath := make(map[string]service.RouteRow, len(rows))

	for _, row := range rows {
		if row.Synthetic {
			continue
		}

		byPath[row.FullPath] = row
	}

	return byPath
}
