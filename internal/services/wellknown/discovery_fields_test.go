// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wellknown

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
)

func discoveryResolveInputs(cfg *config.Config) resolve.ResolveInputs {
	id, err := localidentity.Derive(cfg.PublicOrigin, cfg.ExternalBasePath)
	if err != nil {
		panic("discoveryResolveInputs: " + err.Error())
	}

	return resolve.ResolveInputs{
		LocalIdentity:     id,
		RouteOpts:         service.RouteOptsFromConfig(cfg),
		TokenExchangePath: cfg.TokenExchange.Path,
		CodeFlow:          policy.NewCodeFlow(),
	}
}

func TestDiscoveryFields_DevConfigEmptyBasePath(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PublicOrigin = "http://fields.test"
	cfg.ExternalBasePath = ""
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(Inputs{Resolve: discoveryResolveInputs(cfg)}, map[string]any{}, log)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	t.Cleanup(func() { _ = svc.Close() }) //nolint:errcheck // test cleanup: repository close

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var disc spec.Discovery
	if err := json.Unmarshal(rec.Body.Bytes(), &disc); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if !disc.Enabled {
		t.Fatal("expected enabled discovery")
	}

	if disc.EndPoint != "http://fields.test/ocm" {
		t.Errorf("EndPoint = %q", disc.EndPoint)
	}

	if disc.TokenEndPoint != "http://fields.test/ocm/token" {
		t.Errorf("TokenEndPoint = %q", disc.TokenEndPoint)
	}

	path, ok := disc.ResourceTypes[0].Protocols.StringRole("webdav")
	if !ok || path != "/webdav/ocm/" {
		t.Errorf("webdav protocol = %q, ok=%v", path, ok)
	}
}

func TestDiscoveryFields_BasePathMount(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PublicOrigin = "http://fields.test"
	cfg.ExternalBasePath = "/ocm"
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(Inputs{Resolve: discoveryResolveInputs(cfg)}, map[string]any{}, log)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	t.Cleanup(func() { _ = svc.Close() }) //nolint:errcheck // test cleanup: repository close

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)

	var disc spec.Discovery
	if err := json.Unmarshal(rec.Body.Bytes(), &disc); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if disc.EndPoint != "http://fields.test/ocm/ocm" {
		t.Errorf("EndPoint = %q", disc.EndPoint)
	}

	if disc.TokenEndPoint != "http://fields.test/ocm/ocm/token" {
		t.Errorf("TokenEndPoint = %q", disc.TokenEndPoint)
	}

	path, ok := disc.ResourceTypes[0].Protocols.StringRole("webdav")
	if !ok || path != "/ocm/webdav/ocm/" {
		t.Errorf("webdav protocol = %q, ok=%v", path, ok)
	}
}

func TestDiscoveryFields_HandlerCoreDocument(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PublicOrigin = "http://fields.test"
	cfg.ExternalBasePath = ""
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(Inputs{Resolve: discoveryResolveInputs(cfg)}, map[string]any{}, log)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	t.Cleanup(func() { _ = svc.Close() }) //nolint:errcheck // test cleanup: repository close

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var disc spec.Discovery
	if err := json.Unmarshal(rec.Body.Bytes(), &disc); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if !disc.Enabled {
		t.Fatal("expected enabled discovery")
	}

	if disc.APIVersion != "1.4.0" {
		t.Errorf("APIVersion = %q, want 1.4.0", disc.APIVersion)
	}

	if disc.Provider != "OpenCloudMesh" {
		t.Errorf("Provider = %q, want OpenCloudMesh", disc.Provider)
	}

	got := append([]string(nil), disc.Capabilities...)
	sort.Strings(got)

	want := []string{"exchange-token", "invites"}
	if len(got) != len(want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("capabilities = %v, want %v", got, want)
		}
	}
}
