// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package realip

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestUsesHTTPS_NilRequest(t *testing.T) {
	t.Parallel()

	if RequestUsesHTTPS(nil) {
		t.Fatal("expected false for nil request")
	}
}

func TestRequestUsesHTTPS_IgnoresURLSchemeWithoutValidatedContext(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://cloud.example.com/path", nil)
	req.URL.Scheme = "https"

	if RequestUsesHTTPS(req) {
		t.Fatal("expected false without direct TLS or middleware-validated HTTPS context")
	}
}

func TestRequestUsesHTTPS_DirectTLS(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://backend/path", nil)
	req.TLS = &tls.ConnectionState{}

	if !RequestUsesHTTPS(req) {
		t.Fatal("expected true for direct TLS without validated forwarding context")
	}
}

func TestRequestUsesHTTPS_ValidatedContextOnly(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://backend/path", nil)
	req = req.WithContext(contextWithValidatedHTTPS(req.Context()))

	if !RequestUsesHTTPS(req) {
		t.Fatal("expected true when validated HTTPS context is set")
	}
}
