package wiring_test

import (
	"context"
	tscfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/cfg"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func strictSSRFCfg(port int) *config.Config {
	cfg := tscfg.DevConfigNoSignatures(port)
	cfg.OutboundHTTP.SSRF.Mode = "strict"
	cfg.OutboundHTTP.DerivedSSRFMode = "strict"
	return cfg
}

func TestOutboundParity_OverrideAffectsSSRF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Run("OutboundOverride SSRF=off allows localhost request", func(t *testing.T) {
		result, err := wiring.Build(strictSSRFCfg(18090), tslog.DiscardLogger(), harnessBuildOpts())
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatalf("failed to build request: %v", err)
		}
		resp, reqErr := result.Deps.HTTPClient.Do(context.Background(), req)
		if reqErr != nil {
			t.Fatalf("expected localhost request to succeed with SSRF=off override, got: %v", reqErr)
		}
		resp.Body.Close()
	})

	t.Run("without OutboundOverride SSRF=strict blocks localhost request", func(t *testing.T) {
		opts := harnessBuildOpts()
		opts.OutboundOverride = nil
		result, err := wiring.Build(strictSSRFCfg(18091), tslog.DiscardLogger(), opts)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatalf("failed to build request: %v", err)
		}
		_, reqErr := result.Deps.HTTPClient.Do(context.Background(), req)
		if reqErr == nil {
			t.Fatal("expected SSRF error blocking localhost, but request succeeded")
		}
		if !httpclient.IsSSRFError(reqErr) {
			t.Errorf("expected an SSRF error, got: %v", reqErr)
		}
	})
}

func TestOutboundParity_OverrideHonorsTLSRoots(t *testing.T) {
	cfg := tscfg.DevConfigNoSignatures(18092)
	cfg.OutboundHTTP.TLSRootCAFile = "/nonexistent/fake-ca.pem"

	_, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("bootstrap must succeed when OutboundOverride has empty CA paths: %v", err)
	}
}

func TestOutboundParity_BaseConfigTLSRootsWithoutOverride(t *testing.T) {
	cfg := tscfg.DevConfigNoSignatures(18093)
	cfg.OutboundHTTP.TLSRootCAFile = "/nonexistent/fake-ca.pem"

	opts := harnessBuildOpts()
	opts.OutboundOverride = nil
	_, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
	if err == nil {
		t.Fatal("bootstrap must fail when cfg.OutboundHTTP.TLSRootCAFile is invalid and no override is set")
	}
}
