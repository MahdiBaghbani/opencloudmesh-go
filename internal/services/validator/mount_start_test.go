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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/passive"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
)

func TestMountValidatorRoutes_StartPageGET(t *testing.T) {
	t.Parallel()

	r := chi.NewRouter()
	mountValidatorRoutes(r, passive.NewHandler(openMountTestStore(t), nil), nil, nil, nil)

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

func TestValidatorService_MountsStartPage(t *testing.T) {
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

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
