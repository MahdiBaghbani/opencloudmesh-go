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

func TestHandleReportRetention_NotTerminal409(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-patch-not-terminal"
	tier := validatorcore.RetentionTierForever
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateCreated,
		OptInPermanent: true,
		RetentionTier:  &tier,
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

	assertNotTerminalUnchanged(t, rec, store, runID, &tier, nil, nil)
}

func TestHandleReportLock_NotTerminal409(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-lock-not-terminal"
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StateCreated,
		OptInPermanent: true,
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/report/"+runID+"/lock", nil)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	assertNotTerminalUnchanged(t, rec, store, runID, nil, nil, nil)
}

func TestHandleReportLock_NotTerminalLockedStill409(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-lock-not-terminal-locked"
	lockedAt := time.Now().Unix()
	tier := validatorcore.RetentionTier30
	expires := lockedAt + 30*validatorcore.SecondsPerDay
	seedReportRun(t, store, &validatorcore.TestRun{
		TestRunID:         runID,
		State:             validatorcore.StateCreated,
		OptInPermanent:    true,
		RetentionTier:     &tier,
		RetentionLockedAt: &lockedAt,
		ExpiresAt:         &expires,
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/report/"+runID+"/lock", nil)
	rec := httptest.NewRecorder()
	newReportTestRouter(t, h).ServeHTTP(rec, req)

	assertNotTerminalUnchanged(t, rec, store, runID, &tier, &lockedAt, &expires)
}

func assertNotTerminalUnchanged(
	t *testing.T,
	rec *httptest.ResponseRecorder,
	store *validatorcore.Core,
	runID string,
	wantTier *string,
	wantLockedAt *int64,
	wantExpires *int64,
) {
	t.Helper()

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != codeReportNotTerminal {
		t.Fatalf("error = %q, want %q", payload["error"], codeReportNotTerminal)
	}

	row, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !sameOptionalString(row.RetentionTier, wantTier) {
		t.Fatalf("retention_tier = %v, want %v", row.RetentionTier, wantTier)
	}

	if !sameOptionalInt64(row.RetentionLockedAt, wantLockedAt) {
		t.Fatalf("retention_locked_at = %v, want %v", row.RetentionLockedAt, wantLockedAt)
	}

	if !sameOptionalInt64(row.ExpiresAt, wantExpires) {
		t.Fatalf("expires_at = %v, want %v", row.ExpiresAt, wantExpires)
	}
}

func sameOptionalString(got, want *string) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}

	return *got == *want
}

func sameOptionalInt64(got, want *int64) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}

	return *got == *want
}
