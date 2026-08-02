// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func newTestAuthHandler(t *testing.T) (*AuthHandler, identity.PartyRepo, identity.SessionRepo, *identity.UserAuth) {
	t.Helper()

	repo := identity.NewMemoryPartyRepo()
	sessions := identity.NewMemorySessionRepo()
	auth := identity.NewUserAuthFast()

	return NewAuthHandler(repo, sessions, auth), repo, sessions, auth
}

func seedUser(t *testing.T, repo identity.PartyRepo, auth *identity.UserAuth, username, password string) *identity.User { //nolint:unparam // test fixture helper: username kept for fixture signature uniformity; all current callers pass "alice"
	t.Helper()

	ctx := context.Background()

	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	user := &identity.User{
		Username:     username,
		PasswordHash: hash,
		DisplayName:  username,
		Role:         "user",
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create user: %v", err)
	}

	return user
}

func TestAuthHandler_Login_Success(t *testing.T) {
	handler, repo, _, auth := newTestAuthHandler(t)
	user := seedUser(t, repo, auth, "alice", "secret123")

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

	var resp LoginResponse
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Token == "" {
		t.Error("expected non-empty token")
	}

	if resp.User.ID != user.ID {
		t.Errorf("user id: got %q, want %q", resp.User.ID, user.ID)
	}

	if resp.User.Username != "alice" {
		t.Errorf("username: got %q, want alice", resp.User.Username)
	}

	cookies := res.Cookies()

	var sessionCookie *http.Cookie

	for _, c := range cookies {
		if c.Name == "session" {
			sessionCookie = c
			break
		}
	}

	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Error("expected session cookie to be set")
	}
}

func TestAuthHandler_Login_InvalidCredentials(t *testing.T) {
	handler, repo, _, auth := newTestAuthHandler(t)
	seedUser(t, repo, auth, "alice", "secret123")

	body := `{"username":"alice","password":"wrong"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	handler.Login(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuthHandler_Login_MissingCredentials(t *testing.T) {
	handler, _, _, _ := newTestAuthHandler(t) //nolint:dogsled // test: discarding multiple unneeded values

	tests := []struct {
		name string
		body string
	}{
		{"empty username", `{"username":"","password":"secret"}`},
		{"empty password", `{"username":"alice","password":""}`},
		{"invalid json", `{`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/login", bytes.NewBufferString(tt.body))
			w := httptest.NewRecorder()
			handler.Login(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", w.Code)
			}
		})
	}
}

func TestAuthHandler_Login_MethodNotAllowed(t *testing.T) {
	handler, _, _, _ := newTestAuthHandler(t) //nolint:dogsled // test: discarding multiple unneeded values

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/auth/login", nil)
	w := httptest.NewRecorder()
	handler.Login(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestAuthHandler_Logout(t *testing.T) {
	handler, repo, sessions, auth := newTestAuthHandler(t)
	user := seedUser(t, repo, auth, "alice", "secret123")

	ctx := context.Background()

	session, err := sessions.Create(ctx, user.ID, SessionTTL)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)

	w := httptest.NewRecorder()
	handler.Logout(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	_, err = sessions.Get(ctx, session.Token)
	if !errors.Is(err, identity.ErrSessionNotFound) {
		t.Errorf("expected session deleted, got err=%v", err)
	}
}

func TestAuthHandler_Logout_NoSession(t *testing.T) {
	handler, _, _, _ := newTestAuthHandler(t) //nolint:dogsled // test: discarding multiple unneeded values

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/logout", nil)
	w := httptest.NewRecorder()
	handler.Logout(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuthHandler_GetCurrentUser(t *testing.T) {
	handler, repo, sessions, auth := newTestAuthHandler(t)
	user := seedUser(t, repo, auth, "alice", "secret123")

	ctx := context.Background()

	session, err := sessions.Create(ctx, user.ID, SessionTTL)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)

	w := httptest.NewRecorder()
	handler.GetCurrentUser(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.ID != user.ID {
		t.Errorf("id: got %q, want %q", resp.ID, user.ID)
	}

	if resp.Username != "alice" {
		t.Errorf("username: got %q, want alice", resp.Username)
	}
}

func TestAuthHandler_GetCurrentUser_NoSession(t *testing.T) {
	handler, _, _, _ := newTestAuthHandler(t) //nolint:dogsled // test: discarding multiple unneeded values

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/auth/me", nil)
	w := httptest.NewRecorder()
	handler.GetCurrentUser(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*http.Request)
		want  string
	}{
		{
			name: "bearer header",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer tok-abc")
			},
			want: "tok-abc",
		},
		{
			name: "session cookie",
			setup: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: "session", Value: "cookie-tok"}) //nolint:gosec // test fixture: fixed session cookie token on a local test request, not a real credential
			},
			want: "cookie-tok",
		},
		{
			name:  "missing",
			setup: func(_ *http.Request) {},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			tt.setup(req)

			got := extractToken(req)
			if got != tt.want {
				t.Errorf("extractToken: got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAuthHandler_Login_ResponseContentType(t *testing.T) {
	handler, repo, _, auth := newTestAuthHandler(t)
	seedUser(t, repo, auth, "alice", "secret123")

	body := `{"username":"alice","password":"secret123"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	handler.Login(w, req)

	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("expected application/json Content-Type, got %q", ct)
	}
}
