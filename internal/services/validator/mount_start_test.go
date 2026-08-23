// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validator

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/forwardshare"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseshare"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/runner"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/passive"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
)

func TestMountValidatorRoutes_StartPageGET(t *testing.T) {
	t.Parallel()

	r := chi.NewRouter()
	h := passive.NewHandler(openMountTestStore(t), nil)
	h.SetCaps(catalog.FullCaps())
	mountValidatorRoutes(r, h, nil, nil, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, RouteHTMLStart, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `action="/validator/start"`) {
		t.Fatal("mounted start page missing form action")
	}

	if !strings.Contains(body, `name="optInActive"`) {
		t.Fatal("mounted start page missing optInActive")
	}
}

func TestMountValidatorRoutes_StartPOSTStillCreates(t *testing.T) {
	t.Parallel()

	r := chi.NewRouter()
	mountValidatorRoutes(r, passive.NewHandler(openMountTestStore(t), nil), nil, nil, nil)

	body := []byte(`{"target":"https://peer.example"}`)
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		RouteStartCreateSession,
		bytes.NewReader(body),
	)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 body %s", rec.Code, rec.Body.String())
	}

	var created map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	id, ok := created["id"].(string)
	if !ok || id == "" {
		t.Fatal("expected session id from POST /start")
	}
}

func TestValidatorService_StartPageAbsentWithoutCaps(t *testing.T) {
	t.Parallel()

	svc, err := New(Inputs{
		Store: openMountTestStore(t),
		Ratelimit: ratelimit.Inputs{
			KeyFunc: func(*http.Request) string { return "k" },
		},
		Log: slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError})),
	}, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, RouteHTMLStart, nil)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405 when GET start is unmounted", rec.Code)
	}

	if strings.Contains(rec.Body.String(), `name="optInActive"`) {
		t.Fatal("GET /start must not render the start page without capabilities")
	}
}

func TestMountValidatorRoutes_EmptyCapsDoesNotRegisterGetStart(t *testing.T) {
	t.Parallel()

	r := chi.NewRouter()
	h := passive.NewHandler(openMountTestStore(t), nil)
	mountValidatorRoutes(r, h, nil, nil, nil)

	err := chi.Walk(r, func(method, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if method == http.MethodGet && pattern == RouteHTMLStart {
			t.Fatal("GET /start must not be registered when capabilities are empty")
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	for _, route := range passive.MountedAPIRoutesFor(h.Caps()) {
		if route.Method == http.MethodGet && strings.HasSuffix(route.FullPath, "/start") {
			t.Fatal("GET /start must not be advertised when capabilities are empty")
		}
	}

	getReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, RouteHTMLStart, nil)
	getRec := httptest.NewRecorder()
	r.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /start status = %d, want 405 because POST /start remains mounted", getRec.Code)
	}
}

func TestValidatorService_StartPagePresentWithFullCaps(t *testing.T) {
	t.Parallel()

	store := openMountTestStore(t)

	svc, err := New(Inputs{
		Store:         store,
		ActiveRunner:  &runner.Runner{},
		ReverseInvite: newReverseInviteService(t, store),
		ForwardShare:  &forwardshare.Service{},
		ReverseShare:  &reverseshare.Service{},
		Ratelimit: ratelimit.Inputs{
			KeyFunc: func(*http.Request) string { return "k" },
		},
		Log: slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError})),
	}, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, RouteHTMLStart, nil)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
