// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sessiongate

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	tsidentity "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/identity"
)

func TestAuthGate_SessionInfrastructureError_Returns500(t *testing.T) {
	t.Parallel()

	capture := logutil.NewCapturingLogger(slog.LevelWarn)
	logger := capture.Logger

	protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := chi.NewRouter()
	r.Use(NewAuthGate(AuthGateConfig{
		RequireAuth: func(_ string) bool {
			return true
		},
		Log:         logger,
		SessionRepo: &tsidentity.FailingSessionRepo{},
		PartyRepo:   newTestPartyRepo(),
	}))
	r.Get("/api/protected", protected)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/protected", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "session-token"}) //nolint:gosec // test fixture
	req = req.WithContext(appctx.WithLogger(req.Context(), logger))
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}

	if !capture.Contains("error=") {
		t.Fatalf("expected warning with error attribute, got: %s", capture.Output())
	}

	if strings.Contains(rr.Body.String(), tsidentity.ErrUnavailable.Error()) {
		t.Fatalf("response leaked backend error: %s", rr.Body.String())
	}
}

func TestAuthGate_PartyInfrastructureError_Returns500(t *testing.T) {
	t.Parallel()

	capture := logutil.NewCapturingLogger(slog.LevelWarn)
	logger := capture.Logger

	testUserID := "user-123"
	sessionRepo := &testSessionRepo{
		session: &identity.Session{
			Token:     "valid-session-token",
			UserID:    testUserID,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}

	protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := chi.NewRouter()
	r.Use(NewAuthGate(AuthGateConfig{
		RequireAuth: func(_ string) bool {
			return true
		},
		Log:         logger,
		SessionRepo: sessionRepo,
		PartyRepo:   &tsidentity.FailingPartyRepo{},
	}))
	r.Get("/api/protected", protected)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/protected", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "valid-session-token"}) //nolint:gosec // test fixture
	req = req.WithContext(appctx.WithLogger(req.Context(), logger))
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}

	if !capture.Contains("error=") {
		t.Fatalf("expected warning with error attribute, got: %s", capture.Output())
	}

	if strings.Contains(rr.Body.String(), tsidentity.ErrUnavailable.Error()) {
		t.Fatalf("response leaked backend error: %s", rr.Body.String())
	}
}

func TestAuthGate_ExpiredSession_Returns401_NoInfraWarning(t *testing.T) {
	t.Parallel()

	capture := logutil.NewCapturingLogger(slog.LevelWarn)
	logger := capture.Logger

	sessionRepo := &expiredSessionRepo{}

	protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := chi.NewRouter()
	r.Use(NewAuthGate(AuthGateConfig{
		RequireAuth: func(_ string) bool {
			return true
		},
		Log:         logger,
		SessionRepo: sessionRepo,
		PartyRepo:   newTestPartyRepo(),
	}))
	r.Get("/api/protected", protected)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/protected", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "expired-token"}) //nolint:gosec // test fixture
	req = req.WithContext(appctx.WithLogger(req.Context(), logger))
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}

	if capture.Contains("error=") {
		t.Errorf("expected no infra warning for expired session, got: %s", capture.Output())
	}
}
