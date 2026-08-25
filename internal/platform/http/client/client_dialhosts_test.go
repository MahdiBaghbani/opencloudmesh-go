// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package client_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	outboundtestutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/validatorpeer"
)

type staticResolver struct {
	ip net.IP
}

func (r staticResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: r.ip}}, nil
}

func TestDialHosts_RoutesAdvertisedHostToListener(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	advertised := advertisedHostURL(t, server.URL)
	client := outboundtestutil.NewPermissive(nil)
	client.SetDialHosts(validatorpeer.DialHosts())

	resp, err := client.Get(context.Background(), advertised) //nolint:bodyclose // closed by shared helper
	if err != nil {
		t.Fatalf("GET advertised host: %v", err)
	}
	defer outboundtestutil.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestDialHosts_RequiredWhenHostIsUnresolvable(t *testing.T) {
	t.Parallel()

	hits, server := newHitTrackingServer(t)
	advertised := advertisedHostURL(t, server.URL)
	client := outboundtestutil.NewPermissive(nil)

	resp, err := client.Get(context.Background(), advertised) //nolint:bodyclose // closed by shared helper
	if resp != nil {
		defer outboundtestutil.MustClose(t, resp.Body)
	}

	assertUnmappedAdvertisedHost(t, err, hits)
}

func TestDialHosts_UnlikeResolver_DoesNotFeedPrivateIPToSSRF(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	advertised := advertisedHostURL(t, server.URL)

	t.Run("SetResolver to loopback is SSRF blocked", func(t *testing.T) {
		t.Parallel()

		client := outboundtestutil.NewStrictNone(nil)
		client.SetResolver(staticResolver{ip: net.ParseIP("127.0.0.1")})

		resp, err := client.Get(context.Background(), advertised) //nolint:bodyclose // closed by shared helper
		if resp != nil {
			defer outboundtestutil.MustClose(t, resp.Body)
		}

		if !httpclient.IsSSRFError(err) {
			t.Fatalf("expected SSRF error from resolver private IP, got: %v", err)
		}
	})

	t.Run("SetDialHosts reaches listener under strict SSRF", func(t *testing.T) {
		t.Parallel()

		client := outboundtestutil.NewStrictNone(nil)
		client.SetDialHosts(validatorpeer.DialHosts())

		resp, err := client.Get(context.Background(), advertised) //nolint:bodyclose // closed by shared helper
		if err != nil {
			t.Fatalf("GET advertised host with dial map: %v", err)
		}
		defer outboundtestutil.MustClose(t, resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	})
}

func TestDialHosts_DoesNotAllowPrivateIPLiteral(t *testing.T) {
	t.Parallel()

	client := outboundtestutil.NewStrictNone(nil)
	client.SetDialHosts(validatorpeer.DialHosts())

	resp, err := client.Get(context.Background(), "http://127.0.0.1/test") //nolint:bodyclose // closed by shared helper
	if resp != nil {
		defer outboundtestutil.MustClose(t, resp.Body)
	}

	if !httpclient.IsSSRFError(err) {
		t.Fatalf("expected SSRF error for 127.0.0.1 literal, got: %v", err)
	}
}

func TestDialHosts_MixedCaseKeysMap(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	advertised := advertisedHostURL(t, server.URL)
	client := outboundtestutil.NewPermissive(nil)
	client.SetDialHosts(map[string]string{
		"Validator-Peer.TEST": "127.0.0.1",
	})

	resp, err := client.Get(context.Background(), advertised) //nolint:bodyclose // closed by shared helper
	if err != nil {
		t.Fatalf("GET advertised host with mixed-case dial key: %v", err)
	}
	defer outboundtestutil.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestDialHosts_NilOrEmptyClearsSeam(t *testing.T) {
	t.Parallel()

	t.Run("nil map", func(t *testing.T) {
		t.Parallel()

		hits, server := newHitTrackingServer(t)
		advertised := advertisedHostURL(t, server.URL)
		client := outboundtestutil.NewPermissive(nil)
		client.SetDialHosts(validatorpeer.DialHosts())
		client.SetDialHosts(nil)

		resp, err := client.Get(context.Background(), advertised) //nolint:bodyclose // closed by shared helper
		if resp != nil {
			defer outboundtestutil.MustClose(t, resp.Body)
		}

		assertUnmappedAdvertisedHost(t, err, hits)
	})

	t.Run("empty map", func(t *testing.T) {
		t.Parallel()

		hits, server := newHitTrackingServer(t)
		advertised := advertisedHostURL(t, server.URL)
		client := outboundtestutil.NewPermissive(nil)
		client.SetDialHosts(validatorpeer.DialHosts())
		client.SetDialHosts(map[string]string{})

		resp, err := client.Get(context.Background(), advertised) //nolint:bodyclose // closed by shared helper
		if resp != nil {
			defer outboundtestutil.MustClose(t, resp.Body)
		}

		assertUnmappedAdvertisedHost(t, err, hits)
	})
}

func advertisedHostURL(t *testing.T, listenerURL string) string {
	t.Helper()

	parsed, err := url.Parse(listenerURL)
	if err != nil {
		t.Fatalf("parse listener URL: %v", err)
	}

	parsed.Host = net.JoinHostPort(validatorpeer.HostName, parsed.Port())

	return parsed.String()
}

func newHitTrackingServer(t *testing.T) (*atomic.Int32, *httptest.Server) {
	t.Helper()

	hits := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	return hits, server
}

// assertUnmappedAdvertisedHost requires a resolve/dial failure that never
// reaches the fixture listener. A successful ambient resolve that hits the
// listener or returns a response must not pass.
func assertUnmappedAdvertisedHost(t *testing.T, err error, hits *atomic.Int32) {
	t.Helper()

	if hits.Load() != 0 {
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
