// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
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
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Cleanup(func() { srv.Close() })

	t.Run("OutboundOverride SSRF=off allows localhost request", func(t *testing.T) {
		t.Parallel()

		result, err := wiring.Build(strictSSRFCfg(), tslog.DiscardLogger(), harnessBuildOpts())
		if err != nil {
			t.Fatalf("bootstrap failed: %v", err)
		}

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatalf("failed to build request: %v", err)
		}

		resp, reqErr := result.Deps.HTTPClient.Do(context.Background(), req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
		if reqErr != nil {
			t.Fatalf("expected localhost request to succeed with SSRF=off override, got: %v", reqErr)
		}

		tshttp.MustClose(t, resp.Body)
	})

	t.Run("without OutboundOverride SSRF=strict blocks localhost request", func(t *testing.T) {
		t.Parallel()

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

		resp, reqErr := result.Deps.HTTPClient.Do(context.Background(), req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
		if resp != nil {
			defer tshttp.MustClose(t, resp.Body)
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
	t.Parallel()

	cfg := config.DevConfig()
	cfg.OutboundHTTP.TLSRootCAFile = "/nonexistent/fake-ca.pem"

	_, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("bootstrap must succeed when OutboundOverride has empty CA paths: %v", err)
	}
}

func TestOutbound_BaseConfigTLSRootsWithoutOverride(t *testing.T) {
	t.Parallel()

	cfg := config.DevConfig()
	cfg.OutboundHTTP.TLSRootCAFile = "/nonexistent/fake-ca.pem"

	opts := harnessBuildOpts()
	opts.OutboundOverride = nil

	_, err := wiring.Build(cfg, tslog.DiscardLogger(), opts)
	if err == nil {
		t.Fatal("bootstrap must fail when cfg.OutboundHTTP.TLSRootCAFile is invalid and no override is set")
	}
}
