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
		{"/validator/api/session/run-1/abort", false},
		{"/validator/api/session/run-1/abort/extra", true},
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

func TestRouteSpecs_SessionPollPublicAnonymous(t *testing.T) {
	t.Parallel()

	enabled := service.RouteOpts{
		ValidatorEnabled:  true,
		TokenExchangePath: "token",
	}

	var sessionSpec *service.RouteSpec

	for _, spec := range service.RegisteredRouteSpecs(enabled) {
		if spec.Pattern == RouteAPISession {
			sessionSpec = &spec

			break
		}
	}

	if sessionSpec == nil {
		t.Fatal("expected session route spec")
	}

	if sessionSpec.ID != service.RouteIDValidatorAPISession {
		t.Fatalf("ID = %q, want %q", sessionSpec.ID, service.RouteIDValidatorAPISession)
	}

	if sessionSpec.SessionPolicy != service.SessionPublic {
		t.Fatalf("SessionPolicy = %q, want public", sessionSpec.SessionPolicy)
	}

	if sessionSpec.HandlerAuth != service.HandlerAuthNone {
		t.Fatalf("HandlerAuth = %q, want none", sessionSpec.HandlerAuth)
	}

	if sessionSpec.FeatureCondition != service.FeatureValidatorEnabled {
		t.Fatalf("FeatureCondition = %q, want validator enabled gate", sessionSpec.FeatureCondition)
	}

	if service.SessionAuthRequiredForPath("/validator/api/session/run-1", enabled) {
		t.Fatal("expected anonymous access to /validator/api/session/run-1")
	}

	if !service.SessionAuthRequiredForPath("/validator/api/session/run-1/extra", enabled) {
		t.Fatal("expected /validator/api/session/run-1/extra protected via MatchExact")
	}
}

func TestRouteSpecs_SessionGatedByValidatorFeature(t *testing.T) {
	t.Parallel()

	enabled := service.RouteOpts{ValidatorEnabled: true, TokenExchangePath: "token"}
	disabled := service.RouteOpts{ValidatorEnabled: false, TokenExchangePath: "token"}

	if !routeSpecPresent(t, enabled, RouteAPISession) {
		t.Fatal("expected session route when validator enabled")
	}

	if routeSpecPresent(t, disabled, RouteAPISession) {
		t.Fatal("session route must be absent when validator disabled")
	}

	if !service.SessionAuthRequiredForPath("/validator/api/session/run-1", disabled) {
		t.Fatal("expected protected session path when validator disabled")
	}
}

func TestRouteSpecs_SessionInviteClaimPublicAnonymous(t *testing.T) {
	t.Parallel()

	enabled := service.RouteOpts{
		ValidatorEnabled:  true,
		TokenExchangePath: "token",
	}

	var claimSpec *service.RouteSpec

	for _, spec := range service.RegisteredRouteSpecs(enabled) {
		if spec.Pattern == RouteAPISessionInvite {
			claimSpec = &spec

			break
		}
	}

	if claimSpec == nil {
		t.Fatal("expected session invite claim route spec")
	}

	if claimSpec.ID != service.RouteIDValidatorAPISessionInvite {
		t.Fatalf("ID = %q, want %q", claimSpec.ID, service.RouteIDValidatorAPISessionInvite)
	}

	if claimSpec.Method != http.MethodPost {
		t.Fatalf("Method = %q, want POST", claimSpec.Method)
	}

	if claimSpec.SessionPolicy != service.SessionPublic {
		t.Fatalf("SessionPolicy = %q, want public", claimSpec.SessionPolicy)
	}

	if claimSpec.HandlerAuth != service.HandlerAuthRateLimitOnly {
		t.Fatalf("HandlerAuth = %q, want rate limit only", claimSpec.HandlerAuth)
	}

	if claimSpec.FeatureCondition != service.FeatureValidatorEnabled {
		t.Fatalf("FeatureCondition = %q, want validator enabled gate", claimSpec.FeatureCondition)
	}

	if service.SessionAuthRequiredForPath("/validator/api/session/run-1/invite", enabled) {
		t.Fatal("expected anonymous access to /validator/api/session/run-1/invite")
	}

	if !service.SessionAuthRequiredForPath("/validator/api/session/run-1/invite/extra", enabled) {
		t.Fatal("expected /validator/api/session/run-1/invite/extra protected via MatchExact")
	}
}

func TestRouteSpecs_SessionInviteGatedByValidatorFeature(t *testing.T) {
	t.Parallel()

	enabled := service.RouteOpts{ValidatorEnabled: true, TokenExchangePath: "token"}
	disabled := service.RouteOpts{ValidatorEnabled: false, TokenExchangePath: "token"}

	if !routeSpecPresent(t, enabled, RouteAPISessionInvite) {
		t.Fatal("expected session invite claim route when validator enabled")
	}

	if routeSpecPresent(t, disabled, RouteAPISessionInvite) {
		t.Fatal("session invite claim route must be absent when validator disabled")
	}

	if !service.SessionAuthRequiredForPath("/validator/api/session/run-1/invite", disabled) {
		t.Fatal("expected protected claim path when validator disabled")
	}
}
