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

func TestHandleReportRetention_PatchLosesToCommittedLock(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-tier-race"
	finished := time.Now().Unix()
	seedTier := validatorcore.RetentionTier30
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateTerminalPass,
		OptInPermanent: true,
		FinishedAt:     &finished,
		RetentionTier:  &seedTier,
	})

	router := newReportTestRouter(t, h)

	var lockStatus int

	h.afterRetentionPatchReady = func() {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/report/"+runID+"/lock", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		lockStatus = rec.Code
	}

	body := mustJSON(t, map[string]string{"retentionTier": validatorcore.RetentionTier90})
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPatch,
		"/api/report/"+runID+"/retention",
		bytes.NewReader(body),
	)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if lockStatus != http.StatusOK {
		t.Fatalf("lock status = %d, want 200", lockStatus)
	}

	if rec.Code != http.StatusConflict {
		t.Fatalf("patch status = %d, want 409", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != codeRetentionLocked {
		t.Fatalf("error = %q, want %q", payload["error"], codeRetentionLocked)
	}

	row, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if row.RetentionLockedAt == nil {
		t.Fatal("expected retention_locked_at to be set")
	}

	if row.RetentionTier == nil || *row.RetentionTier != seedTier {
		t.Fatalf("retention_tier = %v, want %q", row.RetentionTier, seedTier)
	}
}

func TestHandleReportLock_StaleSnapshotLosesToCommittedPatch(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-lock-stale-snapshot"
	finished := time.Now().Unix()
	seedTier := validatorcore.RetentionTier30
	seedExpires := finished + 30*validatorcore.SecondsPerDay
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateTerminalPass,
		OptInPermanent: true,
		FinishedAt:     &finished,
		RetentionTier:  &seedTier,
		ExpiresAt:      &seedExpires,
	})

	router := newReportTestRouter(t, h)

	var patchStatus int

	h.afterRetentionLockReady = func() {
		body := mustJSON(t, map[string]string{"retentionTier": validatorcore.RetentionTier90})
		req := httptest.NewRequestWithContext(
			t.Context(),
			http.MethodPatch,
			"/api/report/"+runID+"/retention",
			bytes.NewReader(body),
		)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		patchStatus = rec.Code
	}

	lockRec := httptest.NewRecorder()
	router.ServeHTTP(
		lockRec,
		httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/report/"+runID+"/lock", nil),
	)

	if patchStatus != http.StatusOK {
		t.Fatalf("patch status = %d, want 200", patchStatus)
	}

	if lockRec.Code != http.StatusOK {
		t.Fatalf("lock status = %d, want 200", lockRec.Code)
	}

	row, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if row.RetentionLockedAt == nil {
		t.Fatal("expected retention_locked_at to be set")
	}

	if row.RetentionTier == nil || *row.RetentionTier != validatorcore.RetentionTier90 {
		t.Fatalf("retention_tier = %v, want %q", row.RetentionTier, validatorcore.RetentionTier90)
	}

	wantExpires := finished + 90*validatorcore.SecondsPerDay
	if row.ExpiresAt == nil || *row.ExpiresAt != wantExpires {
		t.Fatalf("expires_at = %v, want %d", row.ExpiresAt, wantExpires)
	}
}

func TestHandleReportLock_IdempotentSecondLock200(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-lock-idempotent"
	finished := time.Now().Unix()
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateTerminalPass,
		OptInPermanent: true,
		FinishedAt:     &finished,
	})

	router := newReportTestRouter(t, h)

	first := httptest.NewRecorder()
	router.ServeHTTP(
		first,
		httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/report/"+runID+"/lock", nil),
	)

	if first.Code != http.StatusOK {
		t.Fatalf("first lock status = %d, want 200", first.Code)
	}

	row, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun after first lock: %v", err)
	}

	if row.RetentionLockedAt == nil {
		t.Fatal("expected first lock to set retention_locked_at")
	}

	lockedAt := *row.RetentionLockedAt
	if row.RetentionTier == nil || *row.RetentionTier != validatorcore.DefaultRetentionTier {
		t.Fatalf("retention_tier after first lock = %v, want %q", row.RetentionTier, validatorcore.DefaultRetentionTier)
	}

	second := httptest.NewRecorder()
	router.ServeHTTP(
		second,
		httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/report/"+runID+"/lock", nil),
	)

	if second.Code != http.StatusOK {
		t.Fatalf("second lock status = %d, want 200", second.Code)
	}

	got, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun after second lock: %v", err)
	}

	if got.RetentionLockedAt == nil || *got.RetentionLockedAt != lockedAt {
		t.Fatalf("retention_locked_at = %v, want %d", got.RetentionLockedAt, lockedAt)
	}

	if got.RetentionTier == nil || *got.RetentionTier != validatorcore.DefaultRetentionTier {
		t.Fatalf("retention_tier after second lock = %v, want %q", got.RetentionTier, validatorcore.DefaultRetentionTier)
	}
}
