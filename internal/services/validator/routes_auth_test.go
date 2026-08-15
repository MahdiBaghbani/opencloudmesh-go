// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validator

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity/sessiongate"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func TestRouteSpecs_StartStopSessionPolicy(t *testing.T) {
	t.Parallel()

	enabled := service.RouteOpts{
		ValidatorEnabled:  true,
		TokenExchangePath: "token",
	}

	var startSpec, stopSpec *service.RouteSpec

	for _, spec := range service.RegisteredRouteSpecs(enabled) {
		if spec.Service != string(service.BuildValidator) {
			continue
		}

		switch spec.Pattern {
		case RouteStartCreateSession:
			startSpec = &spec
		case RouteStopSession:
			stopSpec = &spec
		}
	}

	if startSpec == nil || stopSpec == nil {
		t.Fatal("expected start and stop route specs when validator enabled")
	}

	if startSpec.SessionPolicy != service.SessionPublic {
		t.Errorf("start SessionPolicy = %q, want public", startSpec.SessionPolicy)
	}

	if startSpec.HandlerAuth != service.HandlerAuthRateLimitOnly {
		t.Errorf("start HandlerAuth = %q, want rate limit only", startSpec.HandlerAuth)
	}

	if stopSpec.SessionPolicy != service.SessionPublic {
		t.Errorf("stop SessionPolicy = %q, want public", stopSpec.SessionPolicy)
	}

	if stopSpec.HandlerAuth != service.HandlerAuthNone {
		t.Errorf("stop HandlerAuth = %q, want none", stopSpec.HandlerAuth)
	}
}

func TestRouteSpecs_SessionAuthProjection_StartStopPublic(t *testing.T) {
	t.Parallel()

	enabled := service.RouteOpts{
		ValidatorEnabled:  true,
		TokenExchangePath: "token",
	}

	cases := []struct {
		path     string
		wantAuth bool
	}{
		{"/validator/start", false},
		{"/validator/stop", false},
	}

	for _, tc := range cases {
		got := service.SessionAuthRequiredForPath(tc.path, enabled)
		if got != tc.wantAuth {
			t.Errorf("SessionAuthRequiredForPath(%q) = %v, want %v", tc.path, got, tc.wantAuth)
		}
	}
}

func TestRouteSpecs_SessionAuthProjection_StartStopGatedByValidatorFeature(t *testing.T) {
	t.Parallel()

	disabled := service.RouteOpts{
		ValidatorEnabled:  false,
		TokenExchangePath: "token",
	}

	for _, path := range []string{"/validator/start", "/validator/stop"} {
		if !service.SessionAuthRequiredForPath(path, disabled) {
			t.Errorf("SessionAuthRequiredForPath(%q) = false, want true when validator disabled", path)
		}
	}
}

func TestSessionGate_ValidatorStartAnonymousAdmission(t *testing.T) {
	t.Parallel()

	opts := service.RouteOpts{
		ValidatorEnabled:  true,
		TokenExchangePath: "token",
	}
	checker := service.NewSessionAuthChecker(opts)

	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError}))
	partyRepo := identity.NewMemoryPartyRepo()
	sessionRepo := identity.NewMemorySessionRepo()

	r := chi.NewRouter()
	r.Use(sessiongate.NewAuthGate(sessiongate.AuthGateConfig{
		RequireAuth: checker.Required,
		Log:         logger,
		SessionRepo: sessionRepo,
		PartyRepo:   partyRepo,
	}))
	r.Post("/validator/start", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/validator/start", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized {
		t.Fatal("expected anonymous POST /validator/start to reach handler, got 401")
	}

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected handler status 400, got %d", rec.Code)
	}
}
