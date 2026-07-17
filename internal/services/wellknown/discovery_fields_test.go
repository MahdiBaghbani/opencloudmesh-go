package wellknown

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
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
		LocalIdentity:       id,
		RouteOpts:           service.RouteOptsFromConfig(cfg),
		TokenExchangePath:   cfg.TokenExchange.Path,
		OpenCloudMeshPolicy: policy.NewOpenCloudMeshPolicy(cfg),
		RuntimePolicy:       policy.NewRuntimePolicy(cfg, nil),
	}
}

func TestDiscoveryFields_DevConfigEmptyBasePath(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PublicOrigin = "http://fields.test"
	cfg.ExternalBasePath = ""
	cfg.Signature.InboundMode = "strict"
	cfg.Signature.OutboundMode = "strict"
	// DevConfig defaults RequireTokenExchange to true, which populates
	// must-exchange-token and would make the empty-criteria assertion fail for
	// an unrelated reason, so this test disables it to isolate base-path field
	// resolution.
	cfg.RequireTokenExchange = false

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc, err := New(Inputs{Resolve: discoveryResolveInputs(cfg)}, map[string]any{}, log)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })

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
	if !disc.HasCriteria(spec.CriteriaMustUseHTTPSig) {
		t.Errorf("criteria = %v, want must-use-http-sig under strict inbound", disc.Criteria)
	}
}

func TestDiscoveryFields_BasePathMount(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PublicOrigin = "http://fields.test"
	cfg.ExternalBasePath = "/ocm"
	cfg.Signature.InboundMode = "strict"
	cfg.Signature.OutboundMode = "strict"

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc, err := New(Inputs{Resolve: discoveryResolveInputs(cfg)}, map[string]any{}, log)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })

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
	cfg.Signature.InboundMode = "strict"
	cfg.Signature.OutboundMode = "strict"

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc, err := New(Inputs{Resolve: discoveryResolveInputs(cfg)}, map[string]any{}, log)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })

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

	required := []string{"invites", "protocol-object", "notifications"}
	capSet := make(map[string]bool, len(disc.Capabilities))
	for _, cap := range disc.Capabilities {
		capSet[cap] = true
	}
	for _, req := range required {
		if !capSet[req] {
			t.Errorf("expected unconditional capability %q in %v", req, disc.Capabilities)
		}
	}
}
