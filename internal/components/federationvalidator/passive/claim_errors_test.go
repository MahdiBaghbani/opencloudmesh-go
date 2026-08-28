// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestHandleClaimInvite_PayloadLoadFailureDoesNotConsume(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)
	runID := "run-claim-load-fail"
	token := env.seedMinted(t, runID)

	injected := errors.New("injected payload load failure")

	env.store.SetClaimPayloadLoadHook(func() error {
		env.store.SetClaimPayloadLoadHook(nil)

		return injected
	})

	first := doClaim(t, env.handler, runID)
	if first.Code != http.StatusInternalServerError {
		t.Fatalf("first status = %d, want 500 (body %s)", first.Code, first.Body.String())
	}

	if strings.Contains(first.Body.String(), token) {
		t.Fatalf("500 body leaked token: %s", first.Body.String())
	}

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.S1ClaimedAt != nil {
		t.Fatalf("s1_claimed_at = %v after failed load, want nil", run.S1ClaimedAt)
	}

	retry := doClaim(t, env.handler, runID)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want 200 (body %s)", retry.Code, retry.Body.String())
	}

	payload := decodeClaimJSON(t, retry)

	var inviteString string
	if unmarshalErr := json.Unmarshal(payload["inviteString"], &inviteString); unmarshalErr != nil {
		t.Fatalf("inviteString: %v", unmarshalErr)
	}

	if inviteString == "" {
		t.Fatal("retry inviteString is empty")
	}

	second := doClaim(t, env.handler, runID)
	if second.Code != http.StatusGone {
		t.Fatalf("second status = %d, want 410 (body %s)", second.Code, second.Body.String())
	}

	if strings.Contains(env.logs.String(), token) || strings.Contains(env.logs.String(), inviteString) {
		t.Fatalf("logs leaked invite material: %s", env.logs.String())
	}
}

func TestHandleClaimInvite_StoreErrorLogsNoToken(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)
	runID := "run-claim-store-error"
	token := env.seedMinted(t, runID)

	if err := env.store.DB().WithContext(t.Context()).Where("1 = 1").Delete(&store.OutgoingInvite{}).Error; err != nil {
		t.Fatalf("delete outgoing invites: %v", err)
	}

	rec := doClaim(t, env.handler, runID)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}

	if strings.Contains(rec.Body.String(), token) {
		t.Fatalf("500 body leaked token: %s", rec.Body.String())
	}

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.S1ClaimedAt != nil {
		t.Fatalf("s1_claimed_at = %v after missing payload, want nil", run.S1ClaimedAt)
	}

	logs := env.logs.String()
	if strings.Contains(logs, token) {
		t.Fatalf("500 logs leaked token: %s", logs)
	}

	if !strings.Contains(logs, "validator claim failed") {
		t.Fatalf("expected generic claim failure log, got %s", logs)
	}
}

func TestHandleClaimInvite_UnknownSession404(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)

	rec := doClaim(t, env.handler, "missing-run")
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

func TestHandleClaimInvite_NotMinted409(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)
	runID := "run-claim-not-ready"
	now := int64(1_700_000_000)

	if err := env.store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        validatorcore.StateActiveRunning,
		TargetOrigin: claimTestTargetOrigin,
		TargetHost:   claimTestTargetHost,
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := doClaim(t, env.handler, runID)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != validatorcore.CodeSessionNotReady {
		t.Fatalf("error = %q, want %q", payload["error"], validatorcore.CodeSessionNotReady)
	}
}

func TestHandleClaimInvite_MethodNotAllowedAndNoGETRoute(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)
	runID := "run-claim-get"
	token := env.seedMinted(t, runID)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/"+runID+"/invite", nil)
	rec := httptest.NewRecorder()
	claimRouter(env.handler).ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("GET claim must not succeed")
	}

	if strings.Contains(rec.Body.String(), token) {
		t.Fatalf("GET claim leaked token: %s", rec.Body.String())
	}

	direct := httptest.NewRecorder()
	env.handler.HandleClaimInvite(
		direct,
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/"+runID+"/invite", nil),
	)

	if direct.Code != http.StatusMethodNotAllowed {
		t.Fatalf("direct GET status = %d, want 405", direct.Code)
	}
}

func TestMountPlaneARoutes_ClaimIsPostOnlyAndSessionBound(t *testing.T) {
	t.Parallel()

	r := newPlaneATestRouter(t)

	routes, err := EnumeratePlaneARoutes(r)
	if err != nil {
		t.Fatalf("EnumeratePlaneARoutes: %v", err)
	}

	var claimPosts, claimGets int

	for _, route := range routes {
		if !strings.HasSuffix(route.FullPath, "/api/session/{id}/invite") {
			continue
		}

		switch route.Method {
		case http.MethodPost:
			claimPosts++
		case http.MethodGet:
			claimGets++
		}
	}

	if claimPosts != 1 {
		t.Fatalf("POST claim routes = %d, want 1", claimPosts)
	}

	if claimGets != 0 {
		t.Fatalf("GET claim routes = %d, want 0", claimGets)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/run-1/invite", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("mounted GET claim must not succeed")
	}
}
