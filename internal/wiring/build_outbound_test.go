package wiring_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func strictSSRFCfg() *config.Config {
	cfg := config.DevConfig()
	cfg.OutboundHTTP.SSRF.Mode = "strict"

	return cfg
}

func TestOutboundOverride_AffectsSSRF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Run("OutboundOverride SSRF=off allows localhost request", func(t *testing.T) {
		result, err := wiring.Build(strictSSRFCfg(), tslog.DiscardLogger(), harnessBuildOpts())
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

		_ = resp.Body.Close() //nolint:errcheck // test cleanup: response body close
	})

	t.Run("without OutboundOverride SSRF=strict blocks localhost request", func(t *testing.T) {
		opts := harnessBuildOpts()
		opts.OutboundOverride = nil

		result, err := wiring.Build(strictSSRFCfg(), tslog.DiscardLogger(), opts)
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatalf("failed to build request: %v", err)
		}

		resp, reqErr := result.Deps.HTTPClient.Do(context.Background(), req)
		if resp != nil {
			defer resp.Body.Close() //nolint:errcheck // test response body close
		}

		if reqErr == nil {
			t.Fatal("expected SSRF error blocking localhost, but request succeeded")
		}

		if !httpclient.IsSSRFError(reqErr) {
			t.Errorf("expected an SSRF error, got: %v", reqErr)
		}
	})
}

func TestOutboundOverride_HonorsTLSRoots(t *testing.T) {
	cfg := config.DevConfig()
	cfg.OutboundHTTP.TLSRootCAFile = "/nonexistent/fake-ca.pem"

	_, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("bootstrap must succeed when OutboundOverride has empty CA paths: %v", err)
	}
}

func TestOutbound_BaseConfigTLSRootsWithoutOverride(t *testing.T) {
	cfg := config.DevConfig()
	cfg.OutboundHTTP.TLSRootCAFile = "/nonexistent/fake-ca.pem"

	opts := harnessBuildOpts()
	opts.OutboundOverride = nil

	_, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
	if err == nil {
		t.Fatal("bootstrap must fail when cfg.OutboundHTTP.TLSRootCAFile is invalid and no override is set")
	}
}
