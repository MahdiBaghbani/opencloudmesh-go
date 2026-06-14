// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	tsrouting "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/routing"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func TestRoutePathMatrix(t *testing.T) {
	for _, variant := range tsrouting.MatrixVariants() {
		t.Run(variant.Name, func(t *testing.T) {
			ts := harness.StartTestServerWithConfig(t, matrixConfigPatch(variant))
			opts := service.RouteOptsFromConfig(ts.Config)
			if opts != variant.Opts {
				t.Fatalf("RouteOptsFromConfig() = %+v, want %+v", opts, variant.Opts)
			}

			rows := tsrouting.InventoryRows(opts)
			if len(rows) == 0 {
				t.Fatal("expected non-empty route inventory from Routes(opts)")
			}

			for _, row := range rows {
				t.Run(row.ID, func(t *testing.T) {
					probePath := tsrouting.ProbePathFromRow(row)
					method := tsrouting.ProbeMethodFromRow(row)
					status := doProbe(t, ts.BaseURL, method, probePath, nil)

					if status == http.StatusNotFound {
						t.Fatalf("%s %s returned 404; route not mounted at %q", method, probePath, row.FullPath)
					}

					wantAuth := service.SessionAuthRequiredForPath(probePath, opts)
					assertSessionAuthBehavior(t, method, probePath, status, wantAuth, row)
				})
			}

			if opts.ExternalBasePath != "" {
				assertHostRootDiscovery(t, ts.BaseURL, opts.ExternalBasePath)
				assertAppRoutesUnderBasePath(t, ts.BaseURL, opts)
			}
		})
	}
}

func TestRoutePathMatrix_TokenEndpointMatchesAggregate(t *testing.T) {
	cases := []struct {
		name              string
		tokenPath         string
		externalBasePath  string
		wantTokenFullPath string
		patch             func(*config.Config)
	}{
		{
			name:              "default-token",
			tokenPath:         "token",
			wantTokenFullPath: "/ocm/token",
			patch:             nil,
		},
		{
			name:              "custom-token",
			tokenPath:         "auth/exchange",
			wantTokenFullPath: "/ocm/auth/exchange",
			patch: func(cfg *config.Config) {
				ensureServiceConfig(cfg, "ocm", map[string]any{
					"token_exchange": map[string]any{
						"enabled": true,
						"path":    "auth/exchange",
					},
				})
			},
		},
		{
			name:              "nested-token",
			tokenPath:         "token/v2",
			wantTokenFullPath: "/ocm/token/v2",
			patch: func(cfg *config.Config) {
				ensureServiceConfig(cfg, "ocm", map[string]any{
					"token_exchange": map[string]any{
						"enabled": true,
						"path":    "token/v2",
					},
				})
			},
		},
		{
			name:              "base-path-custom-token",
			tokenPath:         "auth/exchange",
			externalBasePath:  "/ocm",
			wantTokenFullPath: "/ocm/ocm/auth/exchange",
			patch: func(cfg *config.Config) {
				cfg.ExternalBasePath = "/ocm"
				ensureServiceConfig(cfg, "ocm", map[string]any{
					"token_exchange": map[string]any{
						"enabled": true,
						"path":    "auth/exchange",
					},
				})
			},
		},
		{
			name:              "base-path-nested-token",
			tokenPath:         "token/v2",
			externalBasePath:  "/ocm",
			wantTokenFullPath: "/ocm/ocm/token/v2",
			patch: func(cfg *config.Config) {
				cfg.ExternalBasePath = "/ocm"
				ensureServiceConfig(cfg, "ocm", map[string]any{
					"token_exchange": map[string]any{
						"enabled": true,
						"path":    "token/v2",
					},
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := harness.StartTestServerWithConfig(t, tc.patch)
			opts := service.RouteOptsFromConfig(ts.Config)
			if opts.TokenExchangePath != tc.tokenPath {
				t.Fatalf("TokenExchangePath = %q, want %q", opts.TokenExchangePath, tc.tokenPath)
			}
			if opts.ExternalBasePath != tc.externalBasePath {
				t.Fatalf("ExternalBasePath = %q, want %q", opts.ExternalBasePath, tc.externalBasePath)
			}

			tokenRow, ok := tsrouting.OCMTokenRow(opts)
			if !ok {
				t.Fatal("Routes(opts) missing token endpoint row")
			}
			if tokenRow.FullPath != tc.wantTokenFullPath {
				t.Fatalf("token aggregate FullPath = %q, want %q", tokenRow.FullPath, tc.wantTokenFullPath)
			}
			tokenPath := tsrouting.ProbePathFromRow(tokenRow)

			status := doProbe(t, ts.BaseURL, http.MethodPost, tokenPath, strings.NewReader("grant_type=ocm_share&client_id=test&code=test"))
			if status == http.StatusNotFound {
				t.Fatalf("token endpoint %q not mounted; aggregate path %q", tokenPath, opts.TokenExchangePath)
			}

			if tc.tokenPath != "token" {
				defaultOpts := service.RouteOpts{
					ExternalBasePath:  opts.ExternalBasePath,
					TokenExchangePath: "token",
				}
				defaultPath, ok := tsrouting.OCMTokenFullPath(defaultOpts)
				if !ok {
					t.Fatal("Routes(opts) missing default token endpoint row")
				}
				altStatus := doProbe(t, ts.BaseURL, http.MethodPost, defaultPath, strings.NewReader("grant_type=ocm_share&client_id=test&code=test"))
				if altStatus != http.StatusNotFound {
					t.Errorf("default token path %q should be unmounted when custom path is %q, got %d", defaultPath, tc.tokenPath, altStatus)
				}
			}
		})
	}
}

func TestRoutePathMatrix_WayfAndAcceptInviteUnderBasePath(t *testing.T) {
	ts := harness.StartTestServerWithConfig(t, func(cfg *config.Config) {
		cfg.ExternalBasePath = "/ocm"
		ensureServiceConfig(cfg, "ui", map[string]any{
			"wayf": map[string]any{"enabled": true},
		})
	})
	opts := service.RouteOptsFromConfig(ts.Config)

	wayfRow, ok := tsrouting.RowByID(opts, "ui-wayf")
	if !ok {
		t.Fatal("Routes(opts) missing ui-wayf row")
	}
	wayfPath := tsrouting.ProbePathFromRow(wayfRow)

	acceptRow, ok := tsrouting.RowByID(opts, "ui-accept-invite")
	if !ok {
		t.Fatal("Routes(opts) missing ui-accept-invite row")
	}
	acceptPath := tsrouting.ProbePathFromRow(acceptRow)

	if service.SessionAuthRequiredForPath(wayfPath, opts) {
		t.Fatalf("expected %q public when WAYF enabled", wayfPath)
	}
	wayfStatus := doProbe(t, ts.BaseURL, http.MethodGet, wayfPath+"?token=abc", nil)
	if wayfStatus == http.StatusNotFound {
		t.Fatalf("WAYF route not mounted at %q", wayfPath)
	}
	if wayfStatus == http.StatusUnauthorized || wayfStatus == http.StatusFound {
		t.Fatalf("expected public WAYF route, got %d", wayfStatus)
	}

	if !service.SessionAuthRequiredForPath(acceptPath, opts) {
		t.Fatalf("expected %q protected when invite accept enabled", acceptPath)
	}
	acceptStatus := doProbe(t, ts.BaseURL, http.MethodGet, acceptPath+"?token=abc&providerDomain=remote.example.com", nil)
	if acceptStatus == http.StatusNotFound {
		t.Fatalf("accept-invite route not mounted at %q", acceptPath)
	}
	if acceptStatus != http.StatusFound {
		t.Fatalf("expected protected accept-invite to redirect to login (302), got %d", acceptStatus)
	}
}

func matrixConfigPatch(variant tsrouting.MatrixVariant) func(*config.Config) {
	return func(cfg *config.Config) {
		cfg.ExternalBasePath = variant.Opts.ExternalBasePath

		if variant.Opts.WayfEnabled {
			ensureServiceConfig(cfg, "ui", map[string]any{
				"wayf": map[string]any{"enabled": true},
			})
		}

		switch variant.Opts.TokenExchangePath {
		case "auth/exchange", "token/v2":
			ensureServiceConfig(cfg, "ocm", map[string]any{
				"token_exchange": map[string]any{
					"enabled": true,
					"path":    variant.Opts.TokenExchangePath,
				},
			})
		}
	}
}

func ensureServiceConfig(cfg *config.Config, name string, patch map[string]any) {
	if cfg.HTTP.Services == nil {
		cfg.HTTP.Services = make(map[string]map[string]any)
	}
	existing := cfg.HTTP.Services[name]
	if existing == nil {
		cfg.HTTP.Services[name] = patch
		return
	}
	for k, v := range patch {
		existing[k] = v
	}
	cfg.HTTP.Services[name] = existing
}

func assertHostRootDiscovery(t *testing.T, baseURL, externalBasePath string) {
	t.Helper()
	for _, path := range tsrouting.HostRootDiscoveryPaths() {
		status := doProbe(t, baseURL, http.MethodGet, path, nil)
		if status != http.StatusOK {
			t.Errorf("host-root discovery %q returned %d, want 200", path, status)
		}

		prefixed := strings.TrimSuffix(externalBasePath, "/") + path
		prefixedStatus := doProbe(t, baseURL, http.MethodGet, prefixed, nil)
		if prefixedStatus == http.StatusOK {
			t.Errorf("discovery must not be served under base path at %q", prefixed)
		}
	}
}

func assertAppRoutesUnderBasePath(t *testing.T, baseURL string, opts service.RouteOpts) {
	t.Helper()

	healthPath, ok := tsrouting.HealthFullPath(opts)
	if !ok {
		t.Fatal("Routes(opts) missing api-healthz row")
	}
	bareOpts := opts
	bareOpts.ExternalBasePath = ""
	bareHealthPath, ok := tsrouting.HealthFullPath(bareOpts)
	if !ok {
		t.Fatal("Routes(opts) missing api-healthz row for host-root probe")
	}

	bareHealth := doProbe(t, baseURL, http.MethodGet, bareHealthPath, nil)
	prefixedHealth := doProbe(t, baseURL, http.MethodGet, healthPath, nil)
	if prefixedHealth != http.StatusOK {
		t.Errorf("app health under base path returned %d, want 200", prefixedHealth)
	}
	if bareHealth == http.StatusOK {
		t.Errorf("app route %q must not be served at host root when external_base_path is %q", bareHealthPath, opts.ExternalBasePath)
	}
}

func assertSessionAuthBehavior(t *testing.T, method, path string, status int, wantAuth bool, row service.RouteRow) {
	t.Helper()

	if wantAuth {
		if isUIProbePath(path) && (method == http.MethodGet || method == http.MethodHead) {
			if status != http.StatusFound {
				t.Errorf("%s %s: expected session-protected UI redirect (302), got %d (row %q)", method, path, status, row.ID)
			}
			return
		}
		if status != http.StatusUnauthorized {
			t.Errorf("%s %s: expected session-protected status 401, got %d (row %q)", method, path, status, row.ID)
		}
		return
	}

	if row.Service == "webdav" {
		if status == http.StatusNotFound {
			t.Errorf("%s %s: webdav route should be mounted (row %q)", method, path, row.ID)
		}
		return
	}

	// OCM protocol routes use handler-level signature auth; session-public probes may return 401 without credentials.
	if status == http.StatusUnauthorized && row.Service != "ocm" {
		t.Errorf("%s %s: expected session-public route, got 401 (row %q)", method, path, row.ID)
	}
}

func isUIProbePath(path string) bool {
	return strings.Contains(path, "/ui/") || strings.HasSuffix(path, "/ui")
}

func doProbe(t *testing.T, baseURL, method, path string, body io.Reader) int {
	t.Helper()

	req, err := http.NewRequest(method, baseURL+path, body)
	if err != nil {
		t.Fatalf("failed to create %s %s request: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestRoutePathMatrix_OCMProtocolRoutesSessionPublic(t *testing.T) {
	ts := harness.StartTestServer(t)
	opts := service.RouteOptsFromConfig(ts.Config)

	for _, row := range tsrouting.InventoryRows(opts) {
		if row.SurfaceClass != service.SurfaceProtocol {
			continue
		}
		probePath := tsrouting.ProbePathFromRow(row)
		if service.SessionAuthRequiredForPath(probePath, opts) {
			t.Errorf("protocol route %q should be session-public, auth required for %q", row.ID, probePath)
		}

		var body io.Reader
		if row.Method == http.MethodPost {
			body = strings.NewReader("grant_type=ocm_share&client_id=test&code=test")
		}
		status := doProbe(t, ts.BaseURL, tsrouting.ProbeMethodFromRow(row), probePath, body)
		if status == http.StatusNotFound {
			t.Fatalf("protocol route %q not mounted at %q", row.ID, probePath)
		}
	}
}

func TestRoutePathMatrix_OCMAuxRoutesPublic(t *testing.T) {
	ts := harness.StartTestServer(t)
	opts := service.DefaultRouteOpts()

	for _, row := range tsrouting.InventoryRows(opts) {
		if row.SurfaceClass != service.SurfaceHelper {
			continue
		}
		probePath := tsrouting.ProbePathFromRow(row)
		status := doProbe(t, ts.BaseURL, tsrouting.ProbeMethodFromRow(row), probePath, nil)
		if status == http.StatusNotFound {
			t.Fatalf("ocm-aux route %q not mounted at %q", row.ID, probePath)
		}
		if service.SessionAuthRequiredForPath(probePath, opts) {
			t.Errorf("ocm-aux route %q should be session-public", row.ID)
		}
	}
}

func TestRoutePathMatrix_WebDAVCompoundPrefixUnderBasePath(t *testing.T) {
	ts := harness.StartTestServerWithConfig(t, func(cfg *config.Config) {
		cfg.ExternalBasePath = "/ocm"
	})
	opts := service.RouteOptsFromConfig(ts.Config)

	var webdavRow *service.RouteRow
	for _, row := range tsrouting.InventoryRows(opts) {
		if row.Service == "webdav" {
			webdavRow = &row
			break
		}
	}
	if webdavRow == nil {
		t.Fatal("expected webdav row in Routes(opts)")
	}

	probePath := tsrouting.ProbePathFromRow(*webdavRow)
	if !strings.HasPrefix(probePath, "/ocm/webdav/ocm/") {
		t.Fatalf("webdav probe path = %q, want /ocm/webdav/ocm/ prefix", probePath)
	}

	status := doProbe(t, ts.BaseURL, http.MethodGet, probePath, nil)
	if status == http.StatusNotFound {
		t.Fatalf("webdav route not mounted at %q", probePath)
	}
	if service.SessionAuthRequiredForPath(probePath, opts) {
		t.Fatalf("webdav route should be session-public at %q", probePath)
	}
	if status != http.StatusUnauthorized && status != http.StatusBadRequest {
		t.Logf("webdav handler auth status = %d at %q (handler-level 401/400 expected without credentials)", status, probePath)
	}
}
