package client

import (
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestNewTransport_MaxConnsAndResponseHeaderTimeout(t *testing.T) {
	cfg := config.OutboundHTTPConfigStrict()
	c := New(&cfg, nil)

	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok || transport == nil {
		t.Fatal("expected *http.Transport")
	}

	if transport.MaxConnsPerHost <= 0 {
		t.Fatalf("MaxConnsPerHost = %d, want positive", transport.MaxConnsPerHost)
	}

	if transport.MaxConnsPerHost != config.DefaultOutboundMaxConnsPerHost {
		t.Fatalf("MaxConnsPerHost = %d, want %d", transport.MaxConnsPerHost, config.DefaultOutboundMaxConnsPerHost)
	}

	if transport.ResponseHeaderTimeout <= 0 {
		t.Fatalf("ResponseHeaderTimeout = %v, want positive", transport.ResponseHeaderTimeout)
	}

	if transport.ResponseHeaderTimeout != config.DefaultOutboundResponseHeaderTimeout {
		t.Fatalf(
			"ResponseHeaderTimeout = %v, want %v",
			transport.ResponseHeaderTimeout,
			config.DefaultOutboundResponseHeaderTimeout,
		)
	}
}
