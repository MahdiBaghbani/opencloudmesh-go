// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validator

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/passive"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestMountValidatorRoutes_ReportAnonymousGET(t *testing.T) {
	t.Parallel()

	store := openMountTestStore(t)
	passiveHandler := passive.NewHandler(store, nil)
	runID := "run-mount-report"
	now := int64(1_700_000_100)
	row := &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateCreated,
		SessionKind:    validatorcore.SessionKindPassiveOnly,
		TargetHost:     "peer.example",
		OptInPermanent: true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := store.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	r := chi.NewRouter()
	mountValidatorRoutes(r, passiveHandler, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/report/"+runID, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("json status = %d, want 200", rec.Code)
	}

	var payload map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["schema"] != "federation_tester_report.v1" {
		t.Fatalf("schema = %v", payload["schema"])
	}

	htmlReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/report/"+runID, nil)
	htmlRec := httptest.NewRecorder()
	r.ServeHTTP(htmlRec, htmlReq)

	if htmlRec.Code != http.StatusOK {
		t.Fatalf("html status = %d, want 200", htmlRec.Code)
	}
}

func TestValidatorService_MountsReportRoute(t *testing.T) {
	t.Parallel()

	store := openMountTestStore(t)
	runID := "run-svc-report"
	now := int64(1_700_000_200)
	row := &validatorcore.TestRun{
		TestRunID:   runID,
		State:       validatorcore.StateCreated,
		SessionKind: validatorcore.SessionKindPassiveOnly,
		TargetHost:  "peer.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := store.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	svc, err := New(Inputs{
		Store: store,
		Ratelimit: ratelimit.Inputs{
			KeyFunc: func(*http.Request) string { return "k" },
		},
		Log: slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError})),
	}, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/report/"+runID, nil)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
