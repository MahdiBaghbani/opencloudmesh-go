package app_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/app"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"

	// Register cache drivers so "memory" is available during bootstrap.
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// testOutboundOverride returns an outbound config safe for localhost connections:
// SSRF off, InsecureSkipVerify true. Use this in tests that must not block
// connections to 127.0.0.1 (e.g., httptest servers).
func testOutboundOverride() *config.OutboundHTTPConfig {
	return &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		SSRFMode:           "off",
		TimeoutMS:          5000,
		ConnectTimeoutMS:   2000,
		MaxRedirects:       1,
		MaxResponseBytes:   1048576,
		InsecureSkipVerify: true,
	}
}

// devOrigin builds a PublicOrigin for a given test port. The port is used
// only for FQDN derivation; no actual listener is started.
func devOrigin(port int) string {
	return fmt.Sprintf("http://localhost:%d", port)
}

// TestBootstrapDepsHarnessOptions calls BootstrapDeps with the WireOptions
// used by the integration test harness (SkipCrypto, SkipPeerTrust, etc.) and
// verifies the call succeeds. This is a behavioral smoke test: it breaks if
// bootstrap.go rejects harness-style options.
func TestBootstrapDepsHarnessOptions(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PublicOrigin = devOrigin(18080)

	deps.ResetDeps()

	result, err := app.BootstrapDeps(cfg, discardLogger(), app.WireOptions{
		FastAuth:                true,
		SkipCrypto:              true,
		SkipPeerTrust:           true,
		SkipSignatureMiddleware: true,
		OutboundOverride:        testOutboundOverride(),
		SkipDiscoveryCache:      true,
	})
	if err != nil {
		t.Fatalf("BootstrapDeps with harness options failed: %v", err)
	}

	// BootstrapResult fields that main.go relies on must remain exported.
	_ = result.RootCAPool
	_ = result.RuntimeEval
}

// TestBootstrapDepsProductionOptions calls BootstrapDeps with zero WireOptions
// (the main.go path) and a dev config with both signature modes set to "off"
// so no key load or generation is attempted. Verifies the call succeeds and
// returns a non-zero BootstrapResult.
func TestBootstrapDepsProductionOptions(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PublicOrigin = devOrigin(18081)
	cfg.Signature.InboundMode = "off"
	cfg.Signature.OutboundMode = "off"

	deps.ResetDeps()

	result, err := app.BootstrapDeps(cfg, discardLogger(), app.WireOptions{})
	if err != nil {
		t.Fatalf("BootstrapDeps with production (zero) options failed: %v", err)
	}

	// main.go reads RuntimeEval immediately after bootstrap to evaluate posture.
	if result.RuntimeEval.DerivedTier == "" {
		t.Error("RuntimeEval.DerivedTier is empty; BootstrapDeps must populate it")
	}
}

// TestBootstrapSkipCrypto verifies that SkipCrypto gates KeyManager, Signer,
// and OutboundPolicy construction. The flag must produce nil deps when true and
// a non-nil OutboundPolicy when false (even with signature modes off).
func TestBootstrapSkipCrypto(t *testing.T) {
	t.Run("SkipCrypto=true produces nil crypto deps", func(t *testing.T) {
		cfg := config.DevConfig()
		cfg.PublicOrigin = devOrigin(18082)

		deps.ResetDeps()
		_, err := app.BootstrapDeps(cfg, discardLogger(), app.WireOptions{
			FastAuth:                true,
			SkipCrypto:              true,
			SkipPeerTrust:           true,
			SkipSignatureMiddleware: true,
			SkipDiscoveryCache:      true,
			OutboundOverride:        testOutboundOverride(),
		})
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := deps.GetDeps()
		if d.KeyManager != nil {
			t.Error("KeyManager must be nil when SkipCrypto=true")
		}
		if d.Signer != nil {
			t.Error("Signer must be nil when SkipCrypto=true")
		}
		if d.OutboundPolicy != nil {
			t.Error("OutboundPolicy must be nil when SkipCrypto=true")
		}
	})

	t.Run("SkipCrypto=false with signature modes off produces non-nil OutboundPolicy", func(t *testing.T) {
		cfg := config.DevConfig()
		cfg.PublicOrigin = devOrigin(18083)
		cfg.Signature.InboundMode = "off"
		cfg.Signature.OutboundMode = "off"

		deps.ResetDeps()
		_, err := app.BootstrapDeps(cfg, discardLogger(), app.WireOptions{
			FastAuth:                true,
			SkipPeerTrust:           true,
			SkipSignatureMiddleware: true,
			SkipDiscoveryCache:      true,
			OutboundOverride:        testOutboundOverride(),
		})
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := deps.GetDeps()
		// Both modes off -> no key loaded/generated.
		if d.KeyManager != nil {
			t.Error("KeyManager must be nil when both signature modes are off")
		}
		if d.Signer != nil {
			t.Error("Signer must be nil when KeyManager is nil")
		}
		// OutboundPolicy is constructed whenever SkipCrypto=false.
		if d.OutboundPolicy == nil {
			t.Error("OutboundPolicy must be non-nil when SkipCrypto=false")
		}
	})
}

// TestBootstrapSkipPeerTrust verifies that SkipPeerTrust gates TrustGroupManager
// and PolicyEngine construction even when cfg.PeerTrust.Enabled is true.
//
// We set PeerTrust.Enabled=true with an empty ConfigPaths slice. BootstrapDeps
// accepts this directly (the file-path validator lives in config.Load, not here).
// The trust group manager is constructed before iterating ConfigPaths, so the
// deps are non-nil after a successful bootstrap with SkipPeerTrust=false.
func TestBootstrapSkipPeerTrust(t *testing.T) {
	peerTrustCfg := func(port int) *config.Config {
		cfg := config.DevConfig()
		cfg.PublicOrigin = devOrigin(port)
		cfg.Signature.InboundMode = "off"
		cfg.Signature.OutboundMode = "off"
		cfg.PeerTrust.Enabled = true
		cfg.PeerTrust.ConfigPaths = []string{} // empty: bootstrap iterates nothing
		return cfg
	}

	t.Run("SkipPeerTrust=true with PeerTrust.Enabled=true produces nil trust deps", func(t *testing.T) {
		deps.ResetDeps()
		_, err := app.BootstrapDeps(peerTrustCfg(18084), discardLogger(), app.WireOptions{
			FastAuth:                true,
			SkipPeerTrust:           true,
			SkipSignatureMiddleware: true,
			SkipDiscoveryCache:      true,
			OutboundOverride:        testOutboundOverride(),
		})
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := deps.GetDeps()
		if d.TrustGroupMgr != nil {
			t.Error("TrustGroupMgr must be nil when SkipPeerTrust=true")
		}
		if d.PolicyEngine != nil {
			t.Error("PolicyEngine must be nil when SkipPeerTrust=true")
		}
	})

	t.Run("SkipPeerTrust=false with PeerTrust.Enabled=true produces non-nil trust deps", func(t *testing.T) {
		deps.ResetDeps()
		_, err := app.BootstrapDeps(peerTrustCfg(18085), discardLogger(), app.WireOptions{
			FastAuth:                true,
			SkipSignatureMiddleware: true,
			SkipDiscoveryCache:      true,
			OutboundOverride:        testOutboundOverride(),
		})
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := deps.GetDeps()
		if d.TrustGroupMgr == nil {
			t.Error("TrustGroupMgr must be non-nil when SkipPeerTrust=false and PeerTrust.Enabled=true")
		}
		if d.PolicyEngine == nil {
			t.Error("PolicyEngine must be non-nil when SkipPeerTrust=false and PeerTrust.Enabled=true")
		}
	})
}

// TestBootstrapSkipSignatureMiddleware verifies that SkipSignatureMiddleware
// gates SignatureMiddleware construction independently of signature config.
func TestBootstrapSkipSignatureMiddleware(t *testing.T) {
	baseCfg := func(port int) *config.Config {
		cfg := config.DevConfig()
		cfg.PublicOrigin = devOrigin(port)
		cfg.Signature.InboundMode = "off"
		cfg.Signature.OutboundMode = "off"
		return cfg
	}

	t.Run("SkipSignatureMiddleware=true produces nil middleware", func(t *testing.T) {
		deps.ResetDeps()
		_, err := app.BootstrapDeps(baseCfg(18086), discardLogger(), app.WireOptions{
			FastAuth:                true,
			SkipPeerTrust:           true,
			SkipSignatureMiddleware: true,
			SkipDiscoveryCache:      true,
			OutboundOverride:        testOutboundOverride(),
		})
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		if deps.GetDeps().SignatureMiddleware != nil {
			t.Error("SignatureMiddleware must be nil when SkipSignatureMiddleware=true")
		}
	})

	t.Run("SkipSignatureMiddleware=false produces non-nil middleware", func(t *testing.T) {
		deps.ResetDeps()
		_, err := app.BootstrapDeps(baseCfg(18087), discardLogger(), app.WireOptions{
			FastAuth:           true,
			SkipPeerTrust:      true,
			SkipDiscoveryCache: true,
			OutboundOverride:   testOutboundOverride(),
		})
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		if deps.GetDeps().SignatureMiddleware == nil {
			t.Error("SignatureMiddleware must be non-nil when SkipSignatureMiddleware=false")
		}
	})
}

// TestBootstrapSkipDiscoveryCache verifies that SkipDiscoveryCache actually
// controls which cache implementation is wired into the discovery client.
// When true, a *cache.NoopCache must be used (no persistence across calls).
// When false, the shared production cache instance must be used instead.
func TestBootstrapSkipDiscoveryCache(t *testing.T) {
	baseCfg := func(port int) *config.Config {
		cfg := config.DevConfig()
		cfg.PublicOrigin = devOrigin(port)
		cfg.Signature.InboundMode = "off"
		cfg.Signature.OutboundMode = "off"
		return cfg
	}

	t.Run("SkipDiscoveryCache=true wires NoopCache to discovery client", func(t *testing.T) {
		deps.ResetDeps()
		_, err := app.BootstrapDeps(baseCfg(18088), discardLogger(), app.WireOptions{
			FastAuth:                true,
			SkipPeerTrust:           true,
			SkipSignatureMiddleware: true,
			SkipDiscoveryCache:      true,
			OutboundOverride:        testOutboundOverride(),
		})
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := deps.GetDeps()
		// The discovery client must receive a no-op cache to prevent cross-test leakage.
		if !d.DiscoveryClient.IsNoopCache() {
			t.Error("expected NoopCache when SkipDiscoveryCache=true, got a different cache")
		}
		// The shared deps Cache is always the production cache instance,
		// regardless of SkipDiscoveryCache. It must never be nil or a no-op.
		if d.Cache == nil {
			t.Fatal("deps.Cache must be non-nil even when SkipDiscoveryCache=true")
		}
	})

	t.Run("SkipDiscoveryCache=false wires shared cache to discovery client", func(t *testing.T) {
		deps.ResetDeps()
		_, err := app.BootstrapDeps(baseCfg(18089), discardLogger(), app.WireOptions{
			FastAuth:                true,
			SkipPeerTrust:           true,
			SkipSignatureMiddleware: true,
			OutboundOverride:        testOutboundOverride(),
		})
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		d := deps.GetDeps()
		if d.DiscoveryClient.IsNoopCache() {
			t.Error("discovery client must not use NoopCache when SkipDiscoveryCache=false")
		}
		// The shared deps Cache must also be non-nil; both the discovery client
		// and the shared cache use the same production cache instance here.
		if d.Cache == nil {
			t.Fatal("deps.Cache must be non-nil when SkipDiscoveryCache=false")
		}
	})
}

// TestBootstrapOutboundOverrideAffectsSSRF verifies that OutboundOverride
// actually controls the SSRF policy of the wired HTTP client, not just which
// config struct is stored. A base config with SSRF=strict blocks loopback;
// the same config with an OutboundOverride (SSRF=off) must allow it.
func TestBootstrapOutboundOverrideAffectsSSRF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// DevConfig with SSRF forced to strict so that outbound localhost is blocked
	// by default. Signature modes off to avoid key generation.
	strictCfg := func(port int) *config.Config {
		cfg := config.DevConfig()
		cfg.PublicOrigin = devOrigin(port)
		cfg.Signature.InboundMode = "off"
		cfg.Signature.OutboundMode = "off"
		cfg.OutboundHTTP.SSRF.Mode = "strict"
		cfg.OutboundHTTP.SSRFMode = "strict"
		return cfg
	}

	t.Run("OutboundOverride SSRF=off allows localhost request", func(t *testing.T) {
		deps.ResetDeps()
		_, err := app.BootstrapDeps(strictCfg(18090), discardLogger(), app.WireOptions{
			FastAuth:                true,
			SkipPeerTrust:           true,
			SkipSignatureMiddleware: true,
			SkipDiscoveryCache:      true,
			OutboundOverride:        testOutboundOverride(), // SSRF off
		})
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatalf("failed to build request: %v", err)
		}
		resp, reqErr := deps.GetDeps().HTTPClient.Do(context.Background(), req)
		if reqErr != nil {
			t.Fatalf("expected localhost request to succeed with SSRF=off override, got: %v", reqErr)
		}
		resp.Body.Close()
	})

	t.Run("without OutboundOverride SSRF=strict blocks localhost request", func(t *testing.T) {
		deps.ResetDeps()
		_, err := app.BootstrapDeps(strictCfg(18091), discardLogger(), app.WireOptions{
			FastAuth:                true,
			SkipPeerTrust:           true,
			SkipSignatureMiddleware: true,
			SkipDiscoveryCache:      true,
			// No OutboundOverride: base config SSRF=strict applies.
		})
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatalf("failed to build request: %v", err)
		}
		_, reqErr := deps.GetDeps().HTTPClient.Do(context.Background(), req)
		if reqErr == nil {
			t.Fatal("expected SSRF error blocking localhost, but request succeeded")
		}
		if !httpclient.IsSSRFError(reqErr) {
			t.Errorf("expected an SSRF error, got: %v", reqErr)
		}
	})
}

// TestBootstrapOutboundOverrideHonorsTLSRoots verifies that OutboundOverride is
// the authoritative source for TLS root CA paths. When cfg.OutboundHTTP carries
// an invalid CA file, bootstrap must still succeed as long as OutboundOverride
// carries no CA paths (falling back to system TLS defaults). This is the
// regression guard for the bug where BuildRootCAPool was called with
// cfg.OutboundHTTP directly instead of the resolved outboundCfg.
func TestBootstrapOutboundOverrideHonorsTLSRoots(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PublicOrigin = devOrigin(18092)
	cfg.Signature.InboundMode = "off"
	cfg.Signature.OutboundMode = "off"
	// A nonexistent CA file in the base config: BuildRootCAPool returns an
	// error when given this path, so bootstrap fails if it ignores the override.
	cfg.OutboundHTTP.TLSRootCAFile = "/nonexistent/fake-ca.pem"

	override := testOutboundOverride() // TLSRootCAFile and TLSRootCADir are both empty

	deps.ResetDeps()
	_, err := app.BootstrapDeps(cfg, discardLogger(), app.WireOptions{
		FastAuth:                true,
		SkipPeerTrust:           true,
		SkipSignatureMiddleware: true,
		SkipDiscoveryCache:      true,
		OutboundOverride:        override,
	})
	if err != nil {
		t.Fatalf("bootstrap must succeed when OutboundOverride has empty CA paths: %v", err)
	}
}

// TestBootstrapBaseConfigTLSRootsAppliedWithoutOverride is the negative
// companion to TestBootstrapOutboundOverrideHonorsTLSRoots. When no
// OutboundOverride is set, an invalid cfg.OutboundHTTP.TLSRootCAFile must cause
// bootstrap to fail, confirming the base-config CA path is still read in the
// non-override path.
func TestBootstrapBaseConfigTLSRootsAppliedWithoutOverride(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PublicOrigin = devOrigin(18093)
	cfg.Signature.InboundMode = "off"
	cfg.Signature.OutboundMode = "off"
	cfg.OutboundHTTP.TLSRootCAFile = "/nonexistent/fake-ca.pem"

	deps.ResetDeps()
	_, err := app.BootstrapDeps(cfg, discardLogger(), app.WireOptions{
		FastAuth:                true,
		SkipPeerTrust:           true,
		SkipSignatureMiddleware: true,
		SkipDiscoveryCache:      true,
		// No OutboundOverride: cfg.OutboundHTTP is the source, so the bad
		// CA file path must trigger a build error.
	})
	if err == nil {
		t.Fatal("bootstrap must fail when cfg.OutboundHTTP.TLSRootCAFile is invalid and no override is set")
	}
}
