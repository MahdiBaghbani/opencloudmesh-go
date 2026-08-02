// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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
