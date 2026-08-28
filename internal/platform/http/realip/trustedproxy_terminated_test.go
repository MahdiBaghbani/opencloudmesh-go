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

func terminatedTrustedProxies(t *testing.T) *TrustedProxies {
	t.Helper()

	tp, err := NewTrustedProxiesStrict([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrustedProxiesStrict: %v", err)
	}

	return tp.EnableStrictForwarded()
}

func TestStrictForwarded_XForwardedFor_TrustedValid(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")

	ip, err := tp.ClientIPFromRequest(req)
	if err != nil {
		t.Fatalf("ClientIPFromRequest: %v", err)
	}

	if ip.String() != "203.0.113.10" {
		t.Errorf("got %s, want 203.0.113.10", ip)
	}
}

func TestStrictForwarded_XForwardedFor_UntrustedIgnoresHeader(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	ip, err := tp.ClientIPFromRequest(req)
	if err != nil {
		t.Fatalf("ClientIPFromRequest: %v", err)
	}

	if ip.String() != "192.168.1.100" {
		t.Errorf("got %s, want 192.168.1.100", ip)
	}
}

func TestStrictForwarded_XForwardedFor_MalformedRejected(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "not-an-ip")

	_, err := tp.ClientIPFromRequest(req)
	if !errors.Is(err, ErrMalformedForwardedHeader) {
		t.Fatalf("error = %v, want %v", err, ErrMalformedForwardedHeader)
	}

	if got := tp.GetClientIP(req); got != nil {
		t.Errorf("GetClientIP = %v, want nil on malformed trusted chain", got)
	}
}

func TestStrictForwarded_XForwardedFor_MissingRejected(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	_, err := tp.ClientIPFromRequest(req)
	if !errors.Is(err, ErrMissingForwardedHeader) {
		t.Fatalf("error = %v, want %v", err, ErrMissingForwardedHeader)
	}
}

func TestStrictForwarded_XForwardedFor_LeftmostSpoofRejected(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 203.0.113.10")

	ip, err := tp.ClientIPFromRequest(req)
	if err != nil {
		t.Fatalf("ClientIPFromRequest: %v", err)
	}

	if ip.String() != "203.0.113.10" {
		t.Errorf("got %s, want 203.0.113.10", ip)
	}
}

func TestStrictForwarded_XForwardedFor_MultiHopTrustedChain(t *testing.T) {
	t.Parallel()

	tp, err := NewTrustedProxiesStrict([]string{"127.0.0.0/8", "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrustedProxiesStrict: %v", err)
	}

	tp = tp.EnableStrictForwarded()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 10.0.0.1")

	ip, err := tp.ClientIPFromRequest(req)
	if err != nil {
		t.Fatalf("ClientIPFromRequest: %v", err)
	}

	if ip.String() != "203.0.113.10" {
		t.Errorf("got %s, want 203.0.113.10", ip)
	}
}

func TestStrictForwarded_XForwardedFor_InconsistentTrustedChainRejected(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "127.0.0.2, 127.0.0.3")

	_, err := tp.ClientIPFromRequest(req)
	if !errors.Is(err, ErrMalformedForwardedHeader) {
		t.Fatalf("error = %v, want %v", err, ErrMalformedForwardedHeader)
	}
}

func TestStrictForwarded_XForwardedFor_SpoofedChainRejected(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10, not-an-ip")

	_, err := tp.ClientIPFromRequest(req)
	if !errors.Is(err, ErrMalformedForwardedHeader) {
		t.Fatalf("error = %v, want %v", err, ErrMalformedForwardedHeader)
	}
}

func TestStrictForwarded_XForwardedProto_TrustedValid(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://backend/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-Proto", "https")

	proto, err := tp.ForwardedProto(req)
	if err != nil {
		t.Fatalf("ForwardedProto: %v", err)
	}

	if proto != "https" {
		t.Errorf("got %q, want https", proto)
	}
}

func TestStrictForwarded_XForwardedProto_UntrustedIgnoresHeader(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://backend/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("X-Forwarded-Proto", "https")

	proto, err := tp.ForwardedProto(req)
	if err != nil {
		t.Fatalf("ForwardedProto: %v", err)
	}

	if proto != "http" {
		t.Errorf("got %q, want http", proto)
	}
}

func TestStrictForwarded_XForwardedProto_MalformedRejected(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-Proto", "ftp")

	_, err := tp.ForwardedProto(req)
	if !errors.Is(err, ErrMalformedForwardedHeader) {
		t.Fatalf("error = %v, want %v", err, ErrMalformedForwardedHeader)
	}
}

func TestStrictForwarded_XForwardedProto_ConflictingRejected(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-Proto", "http, https")

	_, err := tp.ForwardedProto(req)
	if !errors.Is(err, ErrConflictingForwardedHeader) {
		t.Fatalf("error = %v, want %v", err, ErrConflictingForwardedHeader)
	}
}

func TestStrictForwarded_XForwardedHost_TrustedValid(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Host = "backend.local:8080"
	req.Header.Set("X-Forwarded-Host", "cloud.example.com")

	host, err := tp.ForwardedHost(req)
	if err != nil {
		t.Fatalf("ForwardedHost: %v", err)
	}

	if host != "cloud.example.com" {
		t.Errorf("got %q, want cloud.example.com", host)
	}
}

func TestStrictForwarded_XForwardedHost_UntrustedIgnoresHeader(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Host = "backend.local:8080"
	req.Header.Set("X-Forwarded-Host", "evil.example.com")

	host, err := tp.ForwardedHost(req)
	if err != nil {
		t.Fatalf("ForwardedHost: %v", err)
	}

	if host != "backend.local:8080" {
		t.Errorf("got %q, want backend.local:8080", host)
	}
}

func TestStrictForwarded_XForwardedHost_MalformedRejected(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-Host", "https://evil.example.com/path")

	_, err := tp.ForwardedHost(req)
	if !errors.Is(err, ErrMalformedForwardedHeader) {
		t.Fatalf("error = %v, want %v", err, ErrMalformedForwardedHeader)
	}
}

func TestStrictForwarded_XForwardedHost_ConflictingRejected(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-Host", "a.example.com, b.example.com")

	_, err := tp.ForwardedHost(req)
	if !errors.Is(err, ErrConflictingForwardedHeader) {
		t.Fatalf("error = %v, want %v", err, ErrConflictingForwardedHeader)
	}
}

func TestStrictForwarded_XForwardedHost_QueryStringRejected(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-Host", "cloud.example.com?x")

	_, err := tp.ForwardedHost(req)
	if !errors.Is(err, ErrMalformedForwardedHeader) {
		t.Fatalf("error = %v, want %v", err, ErrMalformedForwardedHeader)
	}
}

func TestStrictForwarded_DuplicateHeaderOccurrencesRejected(t *testing.T) {
	t.Parallel()

	tp := terminatedTrustedProxies(t)

	t.Run("X-Forwarded-For", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Add("X-Forwarded-For", "203.0.113.10")
		req.Header.Add("X-Forwarded-For", "198.51.100.20")

		_, err := tp.ClientIPFromRequest(req)
		if !errors.Is(err, ErrConflictingForwardedHeader) {
			t.Fatalf("error = %v, want %v", err, ErrConflictingForwardedHeader)
		}
	})

	t.Run("X-Forwarded-Proto", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Add("X-Forwarded-Proto", "https")
		req.Header.Add("X-Forwarded-Proto", "http")

		_, err := tp.ForwardedProto(req)
		if !errors.Is(err, ErrConflictingForwardedHeader) {
			t.Fatalf("error = %v, want %v", err, ErrConflictingForwardedHeader)
		}
	})

	t.Run("X-Forwarded-Host", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Add("X-Forwarded-Host", "cloud.example.com")
		req.Header.Add("X-Forwarded-Host", "evil.example.com")

		_, err := tp.ForwardedHost(req)
		if !errors.Is(err, ErrConflictingForwardedHeader) {
			t.Fatalf("error = %v, want %v", err, ErrConflictingForwardedHeader)
		}
	})
}

func TestNewTrustedProxiesStrict_AcceptsEmptyTrustedProxies(t *testing.T) {
	t.Parallel()

	_, err := NewTrustedProxiesStrict(nil)
	if err != nil {
		t.Fatalf("empty trusted proxy list should load: %v", err)
	}
}

func TestNonStrictTrustedProxies_PreservesPermissiveXFF(t *testing.T) {
	t.Parallel()

	tp := NewTrustedProxies([]string{"127.0.0.0/8"})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "garbage, 203.0.113.10")

	ip := tp.GetClientIP(req)
	if ip.String() != "203.0.113.10" {
		t.Errorf("got %s, want 203.0.113.10", ip)
	}
}
