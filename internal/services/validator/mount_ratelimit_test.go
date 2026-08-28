// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validator

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/forwardshare"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseshare"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/runner"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/passive"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/memory"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestMountValidatorRoutes_SharedBudgetThenUnlimitedStayOpen(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32

	limiter := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hits.Add(1) > 2 {
				w.WriteHeader(http.StatusTooManyRequests)

				return
			}

			next.ServeHTTP(w, r)
		})
	}

	r := chi.NewRouter()
	h := passive.NewHandler(openMountTestStore(t), nil)
	h.SetCaps(catalog.FullCaps())
	mountValidatorRoutes(r, h, limiter, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}, nil)

	if code := serveStatus(t, r, http.MethodPost, RouteStartCreateSession, `{"target":"https://peer.example"}`); code != http.StatusCreated {
		t.Fatalf("start status = %d, want 201", code)
	}

	if code := serveStatus(t, r, http.MethodGet, "/api/scan?target=https://peer.example", ""); code == http.StatusTooManyRequests {
		t.Fatal("scan must consume shared budget, not 429 on the second hit")
	}

	if code := serveStatus(t, r, http.MethodPost, "/api/session/run-1/invite", ""); code != http.StatusTooManyRequests {
		t.Fatalf("claim status = %d, want 429 after shared budget", code)
	}

	if code := serveStatus(t, r, http.MethodPost, "/api/session/run-1/reverse-invite", `{"inviteString":"x"}`); code != http.StatusTooManyRequests {
		t.Fatalf("paste status = %d, want 429 (accept-starve on the shared window)", code)
	}

	for _, tc := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: RouteHTMLStart},
		{method: http.MethodGet, path: "/api/session/run-1"},
		{method: http.MethodGet, path: RouteAPIManifest},
		{method: http.MethodPost, path: "/api/session/run-1/abort"},
		{method: http.MethodGet, path: RouteAPIStatistics},
		{method: http.MethodPost, path: RouteStopSession},
		{method: http.MethodGet, path: "/api/report/run-1"},
	} {
		if code := serveStatus(t, r, tc.method, tc.path, ""); code == http.StatusTooManyRequests {
			t.Fatalf("%s %s status = 429, want unlimited after shared budget", tc.method, tc.path)
		}
	}
}

func TestMountValidatorRoutes_BurstOnEachLimitedSurface(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{
			name:   "start",
			method: http.MethodPost,
			path:   RouteStartCreateSession,
			body:   `{"target":"https://peer.example"}`,
		},
		{
			name:   "scan",
			method: http.MethodGet,
			path:   "/api/scan?target=https://peer.example",
		},
		{
			name:   "claim",
			method: http.MethodPost,
			path:   "/api/session/run-1/invite",
		},
		{
			name:   "paste",
			method: http.MethodPost,
			path:   "/api/session/run-1/reverse-invite",
			body:   `{"inviteString":"x"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var hits atomic.Int32

			limiter := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if hits.Add(1) > 1 {
						w.WriteHeader(http.StatusTooManyRequests)

						return
					}

					next.ServeHTTP(w, r)
				})
			}

			r := chi.NewRouter()
			h := passive.NewHandler(openMountTestStore(t), nil)
			h.SetCaps(catalog.FullCaps())
			mountValidatorRoutes(r, h, limiter, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}, nil)

			if code := serveStatus(t, r, tc.method, tc.path, tc.body); code == http.StatusTooManyRequests {
				t.Fatalf("%s first request status = 429, want under budget", tc.name)
			}

			if code := serveStatus(t, r, tc.method, tc.path, tc.body); code != http.StatusTooManyRequests {
				t.Fatalf("%s burst status = %d, want 429", tc.name, code)
			}
		})
	}
}

func TestValidatorService_SharedLimiterUsesNestedBucketNotParentDefault(t *testing.T) {
	t.Parallel()

	cfg := config.ValidatorConfig()
	cfg.HTTP.Interceptors["ratelimit"]["profiles"] = map[string]any{
		config.ScanPublicRatelimitProfile: map[string]any{
			config.StartPublicRatelimitBucket: map[string]any{
				"requests_per_window": int64(2),
				"window_seconds":      60,
			},
		},
	}

	store := openMountTestStore(t)
	ctr := memory.New(time.Minute, 0)

	svc, err := New(Inputs{
		Store:               store,
		Config:              cfg,
		InterceptorProfiles: cfg.HTTP.Interceptors,
		ActiveRunner:        &runner.Runner{},
		ReverseInvite:       newReverseInviteService(t, store),
		ForwardShare:        &forwardshare.Service{},
		ReverseShare:        &reverseshare.Service{},
		Ratelimit: ratelimit.Inputs{
			Cache: ctr,
			KeyFunc: func(*http.Request) string {
				return "203.0.113.10"
			},
		},
		Log: slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError})),
	}, map[string]any{
		"ratelimit": map[string]any{
			"profile": config.ScanPublicRatelimitProfile,
		},
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	h := svc.Handler()

	if code := serveStatus(t, h, http.MethodPost, RouteStartCreateSession, `{"target":"https://peer.example"}`); code != http.StatusCreated {
		t.Fatalf("start 1 status = %d, want 201", code)
	}

	if code := serveStatus(t, h, http.MethodGet, "/api/scan?target=https://peer.example", ""); code == http.StatusTooManyRequests {
		t.Fatal("scan must share the nested 2/60 bucket, not trip on the second hit")
	}

	if code := serveStatus(t, h, http.MethodPost, "/api/session/run-1/invite", ""); code != http.StatusTooManyRequests {
		t.Fatalf("claim status = %d, want 429 on nested 2/60 (parent default 100 would still allow)", code)
	}

	if code := serveStatus(t, h, http.MethodPost, "/api/session/run-1/reverse-invite", `{"inviteString":"x"}`); code != http.StatusTooManyRequests {
		t.Fatalf("paste status = %d, want 429 on the shared nested bucket", code)
	}

	if code := serveStatus(t, h, http.MethodGet, RouteAPIManifest, ""); code == http.StatusTooManyRequests {
		t.Fatal("manifest must stay unlimited after the shared bucket is exhausted")
	}

	if code := serveStatus(t, h, http.MethodGet, "/api/session/run-1", ""); code == http.StatusTooManyRequests {
		t.Fatal("poll must stay unlimited after the shared bucket is exhausted")
	}

	if code := serveStatus(t, h, http.MethodPost, "/api/session/run-1/abort", ""); code == http.StatusTooManyRequests {
		t.Fatal("abort must stay unlimited after the shared bucket is exhausted")
	}
}

func TestRouteSpecs_PasteRateLimitOnly(t *testing.T) {
	t.Parallel()

	enabled := service.RouteOpts{
		ValidatorEnabled:  true,
		TokenExchangePath: "token",
	}

	var pasteSpec *service.RouteSpec

	for _, spec := range service.RegisteredRouteSpecs(enabled) {
		if spec.Pattern == RouteAPISessionReverseInvite {
			pasteSpec = &spec

			break
		}
	}

	if pasteSpec == nil {
		t.Fatal("expected paste route spec")
	}

	if pasteSpec.HandlerAuth != service.HandlerAuthRateLimitOnly {
		t.Fatalf("paste HandlerAuth = %q, want rate limit only", pasteSpec.HandlerAuth)
	}

	if len(pasteSpec.Middleware) != 1 || pasteSpec.Middleware[0] != catalog.MiddlewareRateLimit {
		t.Fatalf("paste Middleware = %v, want [ratelimit]", pasteSpec.Middleware)
	}
}

func serveStatus(t *testing.T, h http.Handler, method, path, body string) int {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec.Code
}
