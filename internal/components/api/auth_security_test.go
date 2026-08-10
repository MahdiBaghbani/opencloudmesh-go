// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package api

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	tsidentity "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/identity"
)

func TestAuthHandler_Login_InvalidCredentials(t *testing.T) {
	t.Parallel()
	handler, repo, _, auth := newTestAuthHandler(t)
	seedUser(t, repo, auth, "alice", "secret123")

	capture := logutil.NewCapturingLogger(slog.LevelWarn)
	body := `{"username":"alice","password":"wrong"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	req = req.WithContext(appctx.WithLogger(req.Context(), capture.Logger))
	w := httptest.NewRecorder()

	handler.Login(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}

	if capture.Contains("error=") {
		t.Errorf("expected no infra warning for invalid password, got: %s", capture.Output())
	}
}

func TestAuthHandler_Login_UserNotFound_NoInfraWarning(t *testing.T) {
	t.Parallel()

	capture := logutil.NewCapturingLogger(slog.LevelWarn)
	handler := NewAuthHandler(identity.NewMemoryPartyRepo(), identity.NewMemorySessionRepo(), identity.NewUserAuthFast())

	body := `{"username":"missing","password":"secret"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	req = req.WithContext(appctx.WithLogger(req.Context(), capture.Logger))
	w := httptest.NewRecorder()

	handler.Login(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	if capture.Contains("error=") {
		t.Errorf("expected no infra warning for missing user, got: %s", capture.Output())
	}
}

func TestAuthHandler_Login_InfrastructureError_Returns500(t *testing.T) {
	t.Parallel()

	capture := logutil.NewCapturingLogger(slog.LevelWarn)
	handler := NewAuthHandler(&tsidentity.FailingPartyRepo{}, identity.NewMemorySessionRepo(), identity.NewUserAuthFast())

	body := `{"username":"alice","password":"secret"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	req = req.WithContext(appctx.WithLogger(req.Context(), capture.Logger))
	w := httptest.NewRecorder()

	handler.Login(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}

	if !capture.Contains("error=") {
		t.Fatalf("expected warning with error attribute, got: %s", capture.Output())
	}

	if strings.Contains(w.Body.String(), tsidentity.ErrUnavailable.Error()) {
		t.Fatalf("response leaked backend error: %s", w.Body.String())
	}
}

func TestAuthHandler_Login_RejectsOversizedBody(t *testing.T) {
	t.Parallel()

	handler, _, _, _ := newTestAuthHandler(t) //nolint:dogsled // test: discarding multiple unneeded values
	padding := strings.Repeat("a", maxLoginBodyBytes)
	body := `{"username":"` + padding + `","password":"x"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	handler.Login(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_Login_RejectsValidJSONWithTrailingData(t *testing.T) {
	t.Parallel()

	handler, repo, _, auth := newTestAuthHandler(t)
	seedUser(t, repo, auth, "alice", "secret123")

	validJSON := `{"username":"alice","password":"secret123"}`

	t.Run("oversized trailing returns 413", func(t *testing.T) {
		t.Parallel()

		body := validJSON + strings.Repeat("x", maxLoginBodyBytes)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
		w := httptest.NewRecorder()

		handler.Login(w, req)

		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected 413, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("small trailing non-json returns 400", func(t *testing.T) {
		t.Parallel()

		body := validJSON + "junk"
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/login", bytes.NewBufferString(body))
		w := httptest.NewRecorder()

		handler.Login(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
		}
	})
}

func TestAuthHandler_GetCurrentUser_SessionInfrastructureError_Returns500(t *testing.T) {
	t.Parallel()

	capture := logutil.NewCapturingLogger(slog.LevelWarn)
	handler := NewAuthHandler(identity.NewMemoryPartyRepo(), &tsidentity.FailingSessionRepo{}, identity.NewUserAuthFast())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer session-token")
	req = req.WithContext(appctx.WithLogger(req.Context(), capture.Logger))
	w := httptest.NewRecorder()

	handler.GetCurrentUser(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}

	if !capture.Contains("error=") {
		t.Fatalf("expected warning with error attribute, got: %s", capture.Output())
	}

	if strings.Contains(w.Body.String(), tsidentity.ErrUnavailable.Error()) {
		t.Fatalf("response leaked backend error: %s", w.Body.String())
	}
}

func TestAuthHandler_GetCurrentUser_UserInfrastructureError_Returns500(t *testing.T) {
	t.Parallel()

	capture := logutil.NewCapturingLogger(slog.LevelWarn)
	sessions := identity.NewMemorySessionRepo()
	ctx := context.Background()

	session, err := sessions.Create(ctx, "user-123", SessionTTL)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	handler := NewAuthHandler(&tsidentity.FailingPartyRepo{}, sessions, identity.NewUserAuthFast())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	req = req.WithContext(appctx.WithLogger(req.Context(), capture.Logger))
	w := httptest.NewRecorder()

	handler.GetCurrentUser(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}

	if !capture.Contains("error=") {
		t.Fatalf("expected warning with error attribute, got: %s", capture.Output())
	}

	if strings.Contains(w.Body.String(), tsidentity.ErrUnavailable.Error()) {
		t.Fatalf("response leaked backend error: %s", w.Body.String())
	}
}

func TestAuthHandler_GetCurrentUser_ExpiredSession_NoInfraWarning(t *testing.T) {
	t.Parallel()

	capture := logutil.NewCapturingLogger(slog.LevelWarn)
	sessions := identity.NewMemorySessionRepo()
	ctx := context.Background()

	session, err := sessions.Create(ctx, "user-123", -time.Hour)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	handler := NewAuthHandler(identity.NewMemoryPartyRepo(), sessions, identity.NewUserAuthFast())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	req = req.WithContext(appctx.WithLogger(req.Context(), capture.Logger))
	w := httptest.NewRecorder()

	handler.GetCurrentUser(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	if capture.Contains("error=") {
		t.Errorf("expected no infra warning for expired session, got: %s", capture.Output())
	}
}
