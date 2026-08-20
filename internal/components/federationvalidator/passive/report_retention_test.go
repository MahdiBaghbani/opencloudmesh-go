// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestHandleReportRetention_UnknownTier400(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-tier-unknown"
	finished := time.Now().Unix()
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		OptInPermanent: true,
		FinishedAt:     &finished,
	})

	body := mustJSON(t, map[string]string{"retentionTier": "365"})
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPatch,
		"/api/report/"+runID+"/retention",
		bytes.NewReader(body),
	)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != codeInvalidTier {
		t.Fatalf("error = %q, want %q", payload["error"], codeInvalidTier)
	}
}

func TestHandleReportRetention_AfterLock409(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-tier-locked"
	lockedAt := time.Now().Unix()
	finished := lockedAt
	tier := validatorcore.RetentionTier30
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:         runID,
		OptInPermanent:    true,
		FinishedAt:        &finished,
		RetentionTier:     &tier,
		RetentionLockedAt: &lockedAt,
	})

	body := mustJSON(t, map[string]string{"retentionTier": validatorcore.RetentionTier90})
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPatch,
		"/api/report/"+runID+"/retention",
		bytes.NewReader(body),
	)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != codeRetentionLocked {
		t.Fatalf("error = %q, want %q", payload["error"], codeRetentionLocked)
	}
}

func TestHandleReportRetention_NotPermanent404(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-tier-private"
	seedReportRun(t, store, &validatorcore.TestRun{TestRunID: runID})

	body := mustJSON(t, map[string]string{"retentionTier": validatorcore.RetentionTier30})
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPatch,
		"/api/report/"+runID+"/retention",
		bytes.NewReader(body),
	)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != codeReportNotPublic {
		t.Fatalf("error = %q, want %q", payload["error"], codeReportNotPublic)
	}
}

func TestHandleReportLock_WritesDefaultTierWhenNull(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-lock-default"
	finished := time.Now().Unix()
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateTerminalPass,
		OptInPermanent: true,
		FinishedAt:     &finished,
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/report/"+runID+"/lock", nil)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	row, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if row.RetentionLockedAt == nil {
		t.Fatal("expected retention_locked_at to be set")
	}

	if row.RetentionTier == nil || *row.RetentionTier != validatorcore.DefaultRetentionTier {
		t.Fatalf("retention_tier = %v, want %q", row.RetentionTier, validatorcore.DefaultRetentionTier)
	}
}

func TestHandleReportRetention_MissingRow404(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)
	body := mustJSON(t, map[string]string{"retentionTier": validatorcore.RetentionTier30})
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPatch,
		"/api/report/missing-run/retention",
		bytes.NewReader(body),
	)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != validatorcore.CodeSessionNotFound {
		t.Fatalf("error = %q, want %q", payload["error"], validatorcore.CodeSessionNotFound)
	}
}

func TestHandleReportRetention_Expired410(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-tier-expired"
	harvested := time.Now().Unix()
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateTerminalPass,
		OptInPermanent: true,
		HarvestedAt:    &harvested,
	})

	body := mustJSON(t, map[string]string{"retentionTier": validatorcore.RetentionTier30})
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPatch,
		"/api/report/"+runID+"/retention",
		bytes.NewReader(body),
	)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != codeReportExpired {
		t.Fatalf("error = %q, want %q", payload["error"], codeReportExpired)
	}
}

func TestHandleReportRetention_SuccessPersistsTierAndExpiresAt(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-tier-success"
	finished := int64(1_700_000_000)
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateTerminalPass,
		OptInPermanent: true,
		FinishedAt:     &finished,
	})

	body := mustJSON(t, map[string]string{"retentionTier": validatorcore.RetentionTier7})
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPatch,
		"/api/report/"+runID+"/retention",
		bytes.NewReader(body),
	)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	row, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if row.RetentionTier == nil || *row.RetentionTier != validatorcore.RetentionTier7 {
		t.Fatalf("retention_tier = %v, want %q", row.RetentionTier, validatorcore.RetentionTier7)
	}

	wantExpires := finished + 7*validatorcore.SecondsPerDay
	if row.ExpiresAt == nil || *row.ExpiresAt != wantExpires {
		t.Fatalf("expires_at = %v, want %d", row.ExpiresAt, wantExpires)
	}
}

func TestHandleReportRetention_ForeverClearsExpiresAt(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-tier-forever"
	finished := time.Now().Unix()
	priorExpires := finished + 30*validatorcore.SecondsPerDay
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateTerminalPass,
		OptInPermanent: true,
		FinishedAt:     &finished,
		ExpiresAt:      &priorExpires,
	})

	body := mustJSON(t, map[string]string{"retentionTier": validatorcore.RetentionTierForever})
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPatch,
		"/api/report/"+runID+"/retention",
		bytes.NewReader(body),
	)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	row, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if row.RetentionTier == nil || *row.RetentionTier != validatorcore.RetentionTierForever {
		t.Fatalf("retention_tier = %v, want forever", row.RetentionTier)
	}

	if row.ExpiresAt != nil {
		t.Fatalf("expires_at = %v, want nil", row.ExpiresAt)
	}
}

func TestHandleReportLock_DoesNotWriteExpiresAt(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-lock-expires"
	finished := int64(1_700_000_000)
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateTerminalPass,
		OptInPermanent: true,
		FinishedAt:     &finished,
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/report/"+runID+"/lock", nil)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	row, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if row.RetentionLockedAt == nil {
		t.Fatal("expected retention_locked_at to be set")
	}

	if row.RetentionTier == nil || *row.RetentionTier != validatorcore.DefaultRetentionTier {
		t.Fatalf("retention_tier = %v, want %q", row.RetentionTier, validatorcore.DefaultRetentionTier)
	}

	if row.ExpiresAt != nil {
		t.Fatalf("expires_at = %v, want nil", row.ExpiresAt)
	}
}

func TestUpdateReportRetention_ZeroRowsMissing404(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/api/report/missing-run/retention", nil)
	rec := httptest.NewRecorder()
	tier := validatorcore.RetentionTier30

	ok := h.updateReportRetention(rec, req, "missing-run", validatorcore.ReportRetentionWrite{
		RetentionTier:  &tier,
		UpdatedAt:      time.Now().Unix(),
		ClearExpiresAt: true,
	})
	if ok {
		t.Fatal("expected zero-row update to fail")
	}

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != validatorcore.CodeSessionNotFound {
		t.Fatalf("error = %q, want %q", payload["error"], validatorcore.CodeSessionNotFound)
	}
}

func TestUpdateReportRetention_ZeroRowsNotPublic404(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-update-private"
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID: runID,
		State:     validatorcore.StateTerminalPass,
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/api/report/"+runID+"/retention", nil)
	rec := httptest.NewRecorder()
	tier := validatorcore.RetentionTier30

	ok := h.updateReportRetention(rec, req, runID, validatorcore.ReportRetentionWrite{
		RetentionTier:  &tier,
		UpdatedAt:      time.Now().Unix(),
		ClearExpiresAt: true,
	})
	if ok {
		t.Fatal("expected zero-row private update to fail")
	}

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != codeReportNotPublic {
		t.Fatalf("error = %q, want %q", payload["error"], codeReportNotPublic)
	}
}
