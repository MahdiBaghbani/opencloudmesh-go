// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func newReportTestRouter(t *testing.T, h *Handler) chi.Router {
	t.Helper()

	r := chi.NewRouter()
	r.Method(http.MethodGet, RouteAPIReport, http.HandlerFunc(h.HandleReportJSON))
	r.Method(http.MethodPatch, RouteAPIReportRetention, http.HandlerFunc(h.HandleReportRetention))
	r.Method(http.MethodPost, RouteAPIReportLock, http.HandlerFunc(h.HandleReportLock))
	r.Method(http.MethodGet, RouteHTMLReport, http.HandlerFunc(h.HandleReportHTML))

	return r
}

func seedReportRun(t *testing.T, store *validatorcore.Core, row *validatorcore.TestRun) {
	t.Helper()

	if row.SessionKind == "" {
		row.SessionKind = validatorcore.SessionKindPassiveOnly
	}

	if row.State == "" {
		row.State = validatorcore.StateCreated
	}

	if row.TargetHost == "" {
		row.TargetHost = "peer.example"
	}

	if row.CreatedAt == 0 {
		row.CreatedAt = time.Now().Unix()
	}

	if row.UpdatedAt == 0 {
		row.UpdatedAt = row.CreatedAt
	}

	if err := store.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestHandleReportJSON_SuccessWireKeys(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-report-ok"
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		OptInPermanent: true,
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/report/"+runID, nil)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	assertExactKeys(t, payload, []string{"id", "reportUrl", "retentionTier", "schema", "visibility"})

	var schema string
	if err := json.Unmarshal(payload["schema"], &schema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	if schema != reportSchema {
		t.Fatalf("schema = %q, want %q", schema, reportSchema)
	}

	var reportURL string
	if err := json.Unmarshal(payload["reportUrl"], &reportURL); err != nil {
		t.Fatalf("reportUrl: %v", err)
	}

	if reportURL != "/validator/report/"+runID {
		t.Fatalf("reportUrl = %q, want path hint", reportURL)
	}

	var visibility string
	if err := json.Unmarshal(payload["visibility"], &visibility); err != nil {
		t.Fatalf("visibility: %v", err)
	}

	if visibility != ReportVisibilitySession {
		t.Fatalf("visibility = %q, want %q", visibility, ReportVisibilitySession)
	}
}

func TestHandleReportJSON_PermanentVisibility(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-report-permanent"
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateTerminalPass,
		OptInPermanent: true,
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/report/"+runID, nil)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	assertExactKeys(t, payload, []string{"id", "reportUrl", "retentionTier", "schema", "visibility"})

	var visibility string
	if err := json.Unmarshal(payload["visibility"], &visibility); err != nil {
		t.Fatalf("visibility: %v", err)
	}

	if visibility != ReportVisibilityPermanent {
		t.Fatalf("visibility = %q, want %q", visibility, ReportVisibilityPermanent)
	}
}

func TestHandleReportJSON_Expired410WireKeys(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-report-expired"
	harvested := time.Now().Unix()
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateTerminalPass,
		OptInPermanent: true,
		HarvestedAt:    &harvested,
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/report/"+runID, nil)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", rec.Code)
	}

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	assertExactKeys(t, payload, []string{"id", "schema", "visibility"})

	var visibility string
	if err := json.Unmarshal(payload["visibility"], &visibility); err != nil {
		t.Fatalf("visibility: %v", err)
	}

	if visibility != ReportVisibilityExpired {
		t.Fatalf("visibility = %q, want %q", visibility, ReportVisibilityExpired)
	}
}

func TestHandleReportJSON_UnknownUsesSessionNotFound(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/report/missing-run", nil)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	assertExactKeys(t, payload, []string{"error", "message"})

	var code string
	if err := json.Unmarshal(payload["error"], &code); err != nil {
		t.Fatalf("error: %v", err)
	}

	if code != validatorcore.CodeSessionNotFound {
		t.Fatalf("error = %q, want %q", code, validatorcore.CodeSessionNotFound)
	}
}

func TestHandleReportJSON_NotSavedUsesReportNotPublic(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-report-private"
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID: runID,
		State:     validatorcore.StateTerminalPass,
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/report/"+runID, nil)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	assertExactKeys(t, payload, []string{"error", "message"})

	var code string
	if err := json.Unmarshal(payload["error"], &code); err != nil {
		t.Fatalf("error: %v", err)
	}

	if code != codeReportNotPublic {
		t.Fatalf("error = %q, want %q", code, codeReportNotPublic)
	}
}

func TestHandleManifest_ReportObjectWireKeys(t *testing.T) {
	t.Parallel()

	payload := BuildManifest()

	if payload.Report.HTMLPath != "/validator/report/{id}" {
		t.Fatalf("htmlPath = %q", payload.Report.HTMLPath)
	}

	if payload.Report.APIPath != "/validator/api/report/{id}" {
		t.Fatalf("apiPath = %q", payload.Report.APIPath)
	}

	wire := mustJSON(t, payload.Report)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(wire, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	assertExactKeys(t, raw, []string{"apiPath", "htmlPath"})
}

func TestHandleManifest_RetentionExactValues(t *testing.T) {
	t.Parallel()

	payload := BuildManifest()
	wantTiers := []string{
		validatorcore.RetentionTierForever,
		validatorcore.RetentionTier7,
		validatorcore.RetentionTier14,
		validatorcore.RetentionTier30,
		validatorcore.RetentionTier60,
		validatorcore.RetentionTier90,
	}

	if !reflect.DeepEqual(payload.Retention.Tiers, wantTiers) {
		t.Fatalf("tiers = %v, want %v", payload.Retention.Tiers, wantTiers)
	}

	if payload.Retention.DefaultTier != validatorcore.DefaultRetentionTier {
		t.Fatalf("defaultTier = %q, want %q", payload.Retention.DefaultTier, validatorcore.DefaultRetentionTier)
	}

	if payload.Retention.Clock != "finishedAt" {
		t.Fatalf("clock = %q, want finishedAt", payload.Retention.Clock)
	}

	if payload.Retention.PatchPath != "/validator/api/report/{id}/retention" {
		t.Fatalf("patchPath = %q", payload.Retention.PatchPath)
	}

	if payload.Retention.LockPath != "/validator/api/report/{id}/lock" {
		t.Fatalf("lockPath = %q", payload.Retention.LockPath)
	}

	h := NewHandler(openHandlerTestStore(t), nil)
	h.SetExternalBasePath("/ocm")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/manifest", nil)
	rec := httptest.NewRecorder()
	h.HandleManifest(rec, req)

	var body manifestRouteResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if body.Retention.PatchPath != "/ocm/validator/api/report/{id}/retention" {
		t.Fatalf("prefixed patchPath = %q", body.Retention.PatchPath)
	}

	if body.Retention.LockPath != "/ocm/validator/api/report/{id}/lock" {
		t.Fatalf("prefixed lockPath = %q", body.Retention.LockPath)
	}
}

func TestClassifyReport(t *testing.T) {
	t.Parallel()

	harvested := int64(50)
	expires := int64(100)

	cases := []struct {
		name string
		row  *validatorcore.TestRun
		now  int64
		want string
	}{
		{name: "unknown nil", want: ReportVisibilityUnknown},
		{
			name: "live private is session",
			row:  &validatorcore.TestRun{TestRunID: "s", State: validatorcore.StateCreated},
			want: ReportVisibilitySession,
		},
		{
			name: "live permanent opted in is session",
			row: &validatorcore.TestRun{
				TestRunID:      "live-opt-in",
				State:          validatorcore.StatePassiveRunning,
				OptInPermanent: true,
			},
			want: ReportVisibilitySession,
		},
		{
			name: "terminal opted in is permanent",
			row: &validatorcore.TestRun{
				State:          validatorcore.StateTerminalPass,
				OptInPermanent: true,
			},
			want: ReportVisibilityPermanent,
		},
		{
			name: "terminal opted in harvested is expired",
			row: &validatorcore.TestRun{
				State:          validatorcore.StateTerminalFail,
				OptInPermanent: true,
				HarvestedAt:    &harvested,
			},
			now:  10,
			want: ReportVisibilityExpired,
		},
		{
			name: "terminal opted in past expires_at is expired",
			row: &validatorcore.TestRun{
				State:          validatorcore.StateInterrupted,
				OptInPermanent: true,
				ExpiresAt:      &expires,
			},
			now:  expires,
			want: ReportVisibilityExpired,
		},
		{
			name: "terminal private is not_saved",
			row:  &validatorcore.TestRun{State: validatorcore.StateTerminalPass},
			want: ReportVisibilityNotSaved,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := ClassifyReport(tc.row, tc.now); got != tc.want {
				t.Fatalf("ClassifyReport = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestJoinReportPath_PrefixesExternalBasePath(t *testing.T) {
	t.Parallel()

	got := joinReportPath("/ocm", "validator", "report", "run-1")
	if got != "/ocm/validator/report/run-1" {
		t.Fatalf("joinReportPath = %q", got)
	}
}

func TestHandleReportJSON_AbsoluteURLOnlyWhenSchemePresent(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-report-abs"
	seedReportRun(t, store, &validatorcore.TestRun{TestRunID: runID})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/report/"+runID, nil)
	req.URL.Scheme = "https"
	req.Host = "peer.example"
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	assertExactKeys(t, payload, []string{"id", "reportUrl", "retentionTier", "schema", "url", "visibility"})

	var abs string
	if err := json.Unmarshal(payload["url"], &abs); err != nil {
		t.Fatalf("url: %v", err)
	}

	if abs != "https://peer.example/validator/report/"+runID {
		t.Fatalf("url = %q", abs)
	}
}
