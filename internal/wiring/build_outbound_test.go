// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/validatorpeer"
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

func TestOutboundDialHosts_ReachesValidatorPeer(t *testing.T) {
	t.Parallel()

	peer := validatorpeer.Start(t, validatorpeer.Options{})

	result, err := wiring.Build(config.DevConfig(), tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, peer.URL+"/.well-known/ocm", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}

	resp, reqErr := result.Deps.HTTPClient.Do(context.Background(), req) //nolint:bodyclose // closed by shared helper
	if reqErr != nil {
		t.Fatalf("expected advertised peer host to reach TLS listener, got: %v", reqErr)
	}
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestOutboundDialHosts_RequiredForAdvertisedPeerHost(t *testing.T) {
	t.Parallel()

	peer := validatorpeer.Start(t, validatorpeer.Options{})

	opts := harnessBuildOpts()
	opts.OutboundDialHosts = nil

	result, err := wiring.Build(config.DevConfig(), tslog.DiscardLogger(), opts)
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, peer.URL+"/.well-known/ocm", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}

	resp, reqErr := result.Deps.HTTPClient.Do(context.Background(), req) //nolint:bodyclose // closed by shared helper
	if resp != nil {
		defer tshttp.MustClose(t, resp.Body)
	}

	assertUnmappedAdvertisedPeerHost(t, reqErr, peer)
}

func TestOutboundDialHosts_DoesNotAllowPrivateIPLiteral(t *testing.T) {
	t.Parallel()

	opts := harnessBuildOpts()
	opts.OutboundOverride = nil

	result, err := wiring.Build(strictSSRFCfg(), tslog.DiscardLogger(), opts)
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1/test", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}

	resp, reqErr := result.Deps.HTTPClient.Do(context.Background(), req) //nolint:bodyclose // closed by shared helper
	if resp != nil {
		defer tshttp.MustClose(t, resp.Body)
	}

	if reqErr == nil {
		t.Fatal("expected SSRF error blocking 127.0.0.1 literal")
	}

	if !httpclient.IsSSRFError(reqErr) {
		t.Errorf("expected an SSRF error, got: %v", reqErr)
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

// assertUnmappedAdvertisedPeerHost requires a resolve/dial failure that never
// reaches the validator peer listener. A successful ambient resolve that hits
// the listener or returns a response must not pass.
func assertUnmappedAdvertisedPeerHost(t *testing.T, err error, peer *validatorpeer.Peer) {
	t.Helper()

	if peer.Hits.Load() != 0 {
		t.Fatal("httptest listener was reached without dial hosts; ambient resolve must not silently pass")
	}

	if err == nil {
		t.Fatal("expected resolve/dial failure without dial hosts; ambient resolve must not succeed")
	}

	if httpclient.IsSSRFError(err) {
		t.Fatalf("permissive client must not report SSRF, got: %v", err)
	}

	if !isResolveOrDialFailure(err) {
		t.Fatalf("expected resolve/dial failure without dial hosts, got: %v", err)
	}
}

func isResolveOrDialFailure(err error) bool {
	if httpclient.IsHostUnresolvable(err) {
		return true
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}

	return errors.Is(err, io.EOF)
}
