package wellknown

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
)

const snapshotDiscoveryGolden = "testdata/wellknown_discovery_dev.golden.json"

func TestBehaviorSnapshot_WellknownDiscoveryGolden(t *testing.T) {
	deps.ResetDeps()
	t.Cleanup(deps.ResetDeps)

	cfg := config.DevConfig()
	cfg.PublicOrigin = "http://snapshot.test"
	cfg.ExternalBasePath = ""
	cfg.Signature.InboundMode = "off"
	cfg.Signature.OutboundMode = "off"

	deps.SetDeps(&deps.Deps{
		Config:              cfg,
		RuntimePolicy:       policy.NewRuntimePolicy(cfg, nil),
		OpenCloudMeshPolicy: policy.NewOpenCloudMeshPolicy(cfg),
	})

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc, err := New(map[string]any{}, log)
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

	got := rec.Body.Bytes()
	wantPath := filepath.Join("testdata", "wellknown_discovery_dev.golden.json")
	want, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read golden %s: %v", wantPath, err)
	}

	var gotDisc, wantDisc spec.Discovery
	if err := json.Unmarshal(got, &gotDisc); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if err := json.Unmarshal(want, &wantDisc); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	if !discoveryEqual(gotDisc, wantDisc) {
		t.Fatalf("discovery output drifted from golden %s", snapshotDiscoveryGolden)
	}
}

func discoveryEqual(a, b spec.Discovery) bool {
	aj, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bj, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(aj) == string(bj)
}

func TestWriteWellknownDiscoveryGolden(t *testing.T) {
	if os.Getenv("GOLDEN_WRITE") != "1" {
		t.Skip("set GOLDEN_WRITE=1 to regenerate golden fixture")
	}

	deps.ResetDeps()
	t.Cleanup(deps.ResetDeps)

	cfg := config.DevConfig()
	cfg.PublicOrigin = "http://snapshot.test"
	cfg.ExternalBasePath = ""
	cfg.Signature.InboundMode = "off"
	cfg.Signature.OutboundMode = "off"

	deps.SetDeps(&deps.Deps{
		Config:              cfg,
		RuntimePolicy:       policy.NewRuntimePolicy(cfg, nil),
		OpenCloudMeshPolicy: policy.NewOpenCloudMeshPolicy(cfg),
	})

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc, err := New(map[string]any{}, log)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer svc.Close()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)

	var pretty map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &pretty); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	out, err := json.MarshalIndent(pretty, "", "  ")
	if err != nil {
		t.Fatalf("marshal golden: %v", err)
	}
	out = append(out, '\n')

	wantPath := filepath.Join("testdata", "wellknown_discovery_dev.golden.json")
	if err := os.MkdirAll(filepath.Dir(wantPath), 0755); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}
	if err := os.WriteFile(wantPath, out, 0644); err != nil {
		t.Fatalf("write golden: %v", err)
	}
}
