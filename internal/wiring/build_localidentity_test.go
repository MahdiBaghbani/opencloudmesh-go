package wiring_test

import (
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	tscfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/cfg"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestBuild_LocalIdentityMatchesDerivedSSOT(t *testing.T) {
	cfg := tscfg.DevConfigHarness(18082)
	cfg.ExternalBasePath = "/ocm"

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if result.Deps == nil {
		t.Fatal("Build must return Deps")
	}

	want, err := localidentity.Derive(cfg.PublicOrigin, cfg.ExternalBasePath)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if result.Deps.LocalIdentity != want {
		t.Errorf("Deps.LocalIdentity = %+v, want %+v", result.Deps.LocalIdentity, want)
	}
}

func TestBuild_KeyIDUsesLocalIdentityOrigin(t *testing.T) {
	const messyOrigin = "https://Cloud.Example.COM:443/"

	cfg := tscfg.DevConfigHarness(18085)
	cfg.PublicOrigin = messyOrigin
	cfg.ExternalBasePath = "/ocm"
	cfg.Signature.KeyPath = filepath.Join(t.TempDir(), "signing.pem")

	opts := harnessBuildOpts()
	opts.SkipCrypto = false

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if result.Deps == nil {
		t.Fatal("Build must return Deps")
	}
	if result.Deps.KeyManager == nil {
		t.Fatal("KeyManager must be non-nil when signature modes are on and SkipCrypto=false")
	}

	gotOrigin := result.Deps.LocalIdentity.Origin
	if gotOrigin == cfg.PublicOrigin {
		t.Fatalf("test setup: LocalIdentity.Origin %q must differ from raw PublicOrigin %q", gotOrigin, cfg.PublicOrigin)
	}

	wantKeyID := gotOrigin + "/ocm#key-1"
	if got := result.Deps.KeyManager.GetKeyID(); got != wantKeyID {
		t.Errorf("KeyManager keyId = %q, want %q derived from LocalIdentity.Origin", got, wantKeyID)
	}

	naiveKeyID := cfg.PublicOrigin + "/ocm#key-1"
	if result.Deps.KeyManager.GetKeyID() == naiveKeyID {
		t.Errorf("keyId must not equal naive raw PublicOrigin concat %q", naiveKeyID)
	}

	want, err := localidentity.Derive(cfg.PublicOrigin, cfg.ExternalBasePath)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if result.Deps.LocalIdentity != want {
		t.Errorf("Deps.LocalIdentity = %+v, want %+v", result.Deps.LocalIdentity, want)
	}
}
