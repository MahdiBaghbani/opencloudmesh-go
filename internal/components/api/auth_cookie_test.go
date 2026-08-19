// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func findSessionCookie(t *testing.T, cookies []*http.Cookie) *http.Cookie {
	t.Helper()

	for _, c := range cookies {
		if c.Name == "session" {
			return c
		}
	}

	t.Fatal("expected session cookie to be set")

	return nil
}

func TestAuthHandler_Login_SecureCookie_DirectTLS(t *testing.T) {
	t.Parallel()

	handler, repo, _, auth := newTestAuthHandler(t)
	seedUser(t, repo, auth, "alice", "secret123")

	body := `{"username":"alice","password":"secret123"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.TLS = &tls.ConnectionState{}

	w := httptest.NewRecorder()
	handler.Login(w, req)

	res := w.Result()
	defer tshttp.MustClose(t, res.Body)

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.StatusCode, w.Body.String())
	}

	sessionCookie := findSessionCookie(t, res.Cookies())
	if !sessionCookie.Secure {
		t.Fatal("expected Secure session cookie for direct TLS")
	}
}

func TestAuthHandler_Logout_SecureCookie_DirectTLS(t *testing.T) {
	t.Parallel()

	handler, repo, sessions, auth := newTestAuthHandler(t)
	user := seedUser(t, repo, auth, "alice", "secret123")

	ctx := context.Background()

	session, err := sessions.Create(ctx, user.ID, SessionTTL)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	req.TLS = &tls.ConnectionState{}

	w := httptest.NewRecorder()
	handler.Logout(w, req)

	res := w.Result()
	defer tshttp.MustClose(t, res.Body)

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.StatusCode, w.Body.String())
	}

	sessionCookie := findSessionCookie(t, res.Cookies())
	if !sessionCookie.Secure {
		t.Fatal("expected Secure deletion cookie for direct TLS")
	}
}

func TestAuthHandler_Login_SecureCookie_TerminatedForwardedHTTPS(t *testing.T) {
	t.Parallel()

	handler, repo, _, auth := newTestAuthHandler(t)
	seedUser(t, repo, auth, "alice", "secret123")

	tp, err := realip.NewTrustedProxiesStrict([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrustedProxiesStrict: %v", err)
	}

	loginHandler := tp.EnableStrictForwarded().Middleware(http.HandlerFunc(handler.Login))

	body := `{"username":"alice","password":"secret123"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "cloud.example.com")

	w := httptest.NewRecorder()
	loginHandler.ServeHTTP(w, req)

	res := w.Result()
	defer tshttp.MustClose(t, res.Body)

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.StatusCode, w.Body.String())
	}

	var sessionCookie *http.Cookie

	for _, c := range res.Cookies() {
		if c.Name == "session" {
			sessionCookie = c

			break
		}
	}

	if sessionCookie == nil {
		t.Fatal("expected session cookie to be set")
	}

	if !sessionCookie.Secure {
		t.Fatal("expected Secure session cookie for validated forwarded HTTPS without direct TLS")
	}

	if req.TLS != nil {
		t.Fatal("test request should not use direct TLS")
	}
}

func TestAuthHandler_Login_NonSecureCookie_PlainHTTP(t *testing.T) {
	t.Parallel()

	handler, repo, _, auth := newTestAuthHandler(t)
	seedUser(t, repo, auth, "alice", "secret123")

	body := `{"username":"alice","password":"secret123"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.Login(w, req)

	res := w.Result()
	defer tshttp.MustClose(t, res.Body)

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.StatusCode, w.Body.String())
	}

	sessionCookie := findSessionCookie(t, res.Cookies())
	if sessionCookie.Secure {
		t.Fatal("expected non-Secure session cookie for plain HTTP without validated forwarding")
	}
}

func TestAuthHandler_Login_NonSecureCookie_AbsoluteFormHTTPSSpoof(t *testing.T) {
	t.Parallel()

	handler, repo, _, auth := newTestAuthHandler(t)
	seedUser(t, repo, auth, "alice", "secret123")

	body := `{"username":"alice","password":"secret123"}`
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"http://cloud.example.com/api/auth/login",
		bytes.NewBufferString(body),
	)
	req.URL.Scheme = "https"
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.99:12345"

	w := httptest.NewRecorder()
	handler.Login(w, req)

	res := w.Result()
	defer tshttp.MustClose(t, res.Body)

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.StatusCode, w.Body.String())
	}

	sessionCookie := findSessionCookie(t, res.Cookies())
	if sessionCookie.Secure {
		t.Fatal("expected non-Secure session cookie for absolute-form https URL on plain HTTP")
	}
}

func TestAuthHandler_Logout_SecureCookie_TerminatedForwardedHTTPS(t *testing.T) {
	t.Parallel()

	handler, repo, sessions, auth := newTestAuthHandler(t)
	user := seedUser(t, repo, auth, "alice", "secret123")

	ctx := context.Background()

	session, err := sessions.Create(ctx, user.ID, SessionTTL)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	tp, err := realip.NewTrustedProxiesStrict([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewTrustedProxiesStrict: %v", err)
	}

	logoutHandler := tp.EnableStrictForwarded().Middleware(http.HandlerFunc(handler.Logout))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "cloud.example.com")

	w := httptest.NewRecorder()
	logoutHandler.ServeHTTP(w, req)

	res := w.Result()
	defer tshttp.MustClose(t, res.Body)

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.StatusCode, w.Body.String())
	}

	sessionCookie := findSessionCookie(t, res.Cookies())
	if !sessionCookie.Secure {
		t.Fatal("expected Secure deletion cookie for validated forwarded HTTPS without direct TLS")
	}

	if req.TLS != nil {
		t.Fatal("test request should not use direct TLS")
	}
}
