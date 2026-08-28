// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package realip

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func strictTrustedProxyMiddleware(t *testing.T) *TrustedProxies {
	t.Helper()

	tp, err := NewTrustedProxiesStrict([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrustedProxiesStrict: %v", err)
	}

	return tp.EnableStrictForwarded()
}

func serveMiddlewareForwardedHeaders(
	t *testing.T,
	tp *TrustedProxies,
	remoteAddr string,
	setHeaders func(*http.Request),
) (status int, gotScheme, gotHost string, clientIP string, usesHTTPS bool) {
	t.Helper()

	handler := tp.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotScheme = r.URL.Scheme
		gotHost = r.Host
		usesHTTPS = RequestUsesHTTPS(r)

		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://backend.local/path", nil)
	req.RemoteAddr = remoteAddr
	req.Host = "backend.local:8080"
	setHeaders(req)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	ip := tp.GetClientIP(req)
	if ip != nil {
		clientIP = ip.String()
	}

	return rec.Code, gotScheme, gotHost, clientIP, usesHTTPS
}

func assertMiddlewareMissingRequiredForwardedHeader(
	t *testing.T,
	setHeaders func(*http.Request),
	handlerNotCalledMsg string,
) {
	t.Helper()

	tp := strictTrustedProxyMiddleware(t)
	called := false

	handler := tp.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://backend.local/path", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	setHeaders(req)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	if called {
		t.Fatal(handlerNotCalledMsg)
	}

	validationReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://backend.local/path", nil)
	validationReq.RemoteAddr = "127.0.0.1:12345"
	setHeaders(validationReq)

	err := tp.ApplyTrustedForwardedHeaders(validationReq)
	if !errors.Is(err, ErrMissingForwardedHeader) {
		t.Fatalf("ApplyTrustedForwardedHeaders error = %v, want %v", err, ErrMissingForwardedHeader)
	}
}

func TestMiddleware_TrustedValidHeadersApplyToRequest(t *testing.T) {
	t.Parallel()

	tp := strictTrustedProxyMiddleware(t)

	status, gotScheme, gotHost, clientIP, usesHTTPS := serveMiddlewareForwardedHeaders(
		t,
		tp,
		"127.0.0.1:12345",
		func(req *http.Request) {
			req.Header.Set("X-Forwarded-For", "203.0.113.10")
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", "cloud.example.com")
		},
	)

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	if gotScheme != "https" {
		t.Errorf("URL.Scheme = %q, want https", gotScheme)
	}

	if gotHost != "cloud.example.com" {
		t.Errorf("Host = %q, want cloud.example.com", gotHost)
	}

	if clientIP != "203.0.113.10" {
		t.Errorf("GetClientIP = %q, want 203.0.113.10", clientIP)
	}

	if !usesHTTPS {
		t.Fatal("expected RequestUsesHTTPS true after validated forwarded HTTPS")
	}
}

func TestMiddleware_TrustedMissingForwardedHeadersRejected(t *testing.T) {
	t.Parallel()

	tp := strictTrustedProxyMiddleware(t)
	called := false

	handler := tp.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://backend.local/path", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	if called {
		t.Fatal("downstream handler should not run on missing forwarded headers")
	}
}

func TestMiddleware_TrustedMissingXForwardedProtoRejected(t *testing.T) {
	t.Parallel()

	assertMiddlewareMissingRequiredForwardedHeader(
		t,
		func(req *http.Request) {
			req.Header.Set("X-Forwarded-For", "203.0.113.10")
			req.Header.Set("X-Forwarded-Host", "cloud.example.com")
		},
		"downstream handler should not run when X-Forwarded-Proto is missing",
	)
}

func TestMiddleware_TrustedMissingXForwardedHostRejected(t *testing.T) {
	t.Parallel()

	assertMiddlewareMissingRequiredForwardedHeader(
		t,
		func(req *http.Request) {
			req.Header.Set("X-Forwarded-For", "203.0.113.10")
			req.Header.Set("X-Forwarded-Proto", "https")
		},
		"downstream handler should not run when X-Forwarded-Host is missing",
	)
}

func TestMiddleware_TrustedMalformedForwardedForRejected(t *testing.T) {
	t.Parallel()

	tp := strictTrustedProxyMiddleware(t)
	called := false

	handler := tp.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://backend.local/path", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "not-an-ip")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "cloud.example.com")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	if called {
		t.Fatal("downstream handler should not run on malformed forwarded headers")
	}
}

func TestMiddleware_TrustedDuplicateForwardedHeadersRejected(t *testing.T) {
	t.Parallel()

	tp := strictTrustedProxyMiddleware(t)
	called := false

	handler := tp.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://backend.local/path", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Add("X-Forwarded-For", "203.0.113.10")
	req.Header.Add("X-Forwarded-For", "198.51.100.20")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "cloud.example.com")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	if called {
		t.Fatal("downstream handler should not run on duplicate forwarded headers")
	}
}

func TestMiddleware_UntrustedPeerIgnoresForwardedHeaders(t *testing.T) {
	t.Parallel()

	tp := strictTrustedProxyMiddleware(t)

	status, gotScheme, gotHost, clientIP, usesHTTPS := serveMiddlewareForwardedHeaders(
		t,
		tp,
		"192.168.1.50:12345",
		func(req *http.Request) {
			req.Header.Set("X-Forwarded-For", "8.8.8.8")
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", "evil.example.com")
		},
	)

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	if gotScheme != "http" {
		t.Errorf("URL.Scheme = %q, want http", gotScheme)
	}

	if gotHost != "backend.local:8080" {
		t.Errorf("Host = %q, want backend.local:8080", gotHost)
	}

	if clientIP != "192.168.1.50" {
		t.Errorf("GetClientIP = %q, want 192.168.1.50", clientIP)
	}

	if usesHTTPS {
		t.Fatal("expected RequestUsesHTTPS false for untrusted peer")
	}
}

func TestMiddleware_TrustedForwardedHTTPDoesNotSetValidatedHTTPS(t *testing.T) {
	t.Parallel()

	tp := strictTrustedProxyMiddleware(t)

	status, _, _, _, usesHTTPS := serveMiddlewareForwardedHeaders( //nolint:dogsled // helper returns fixed tuple; only status and usesHTTPS matter here
		t,
		tp,
		"127.0.0.1:12345",
		func(req *http.Request) {
			req.Header.Set("X-Forwarded-For", "203.0.113.10")
			req.Header.Set("X-Forwarded-Proto", "http")
			req.Header.Set("X-Forwarded-Host", "cloud.example.com")
		},
	)

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	if usesHTTPS {
		t.Fatal("expected RequestUsesHTTPS false for validated forwarded HTTP")
	}
}

func TestMiddleware_NonStrictTrustedProxiesPassThrough(t *testing.T) {
	t.Parallel()

	tp := NewTrustedProxies([]string{"127.0.0.0/8"})
	called := false

	handler := tp.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true

		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://backend.local/path", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if !called {
		t.Fatal("expected downstream handler to run when strict forwarding is disabled")
	}
}
