// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gormsqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	fedcore "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/core"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/statistics"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func openHandlerTestStore(t *testing.T) *validatorcore.Core {
	t.Helper()

	dsn := fmt.Sprintf(
		"file:%s?mode=memory&cache=shared",
		strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()),
	)

	db, err := gorm.Open(gormsqlite.Open(dsn), &gorm.Config{
		Logger:         logger.Default.LogMode(logger.Silent),
		TranslateError: true,
	})
	if err != nil {
		t.Fatalf("open memory db: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db handle: %v", err)
	}

	sqlDB.SetMaxOpenConns(1)

	if err := validatorcore.MigrateModels(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	core := validatorcore.NewCore(db)
	core.SetSessionConfig(validatorcore.SessionConfig{InFlightPassiveLimit: 10})
	core.SetStatsHostHasher(testFedCore(t))

	return core
}

func testFedCore(t *testing.T) *fedcore.Core {
	t.Helper()

	salt := make([]byte, statistics.RedactionSaltSize)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	c, err := fedcore.New(salt)
	if err != nil {
		t.Fatalf("fedcore.New: %v", err)
	}

	return c
}

func waitForState(t *testing.T, store *validatorcore.Core, ctx context.Context, runID, wantState string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)

	for time.Now().Before(deadline) {
		got, err := store.GetTestRun(ctx, runID)
		if err == nil && got.State == wantState {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	got, err := store.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun while waiting for %q: %v", wantState, err)
	}

	t.Fatalf("state = %q, want %q before deadline", got.State, wantState)
}

func mustJSON(t *testing.T, payload any) []byte {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return body
}

func TestHandleStart_RejectsDualFieldBody(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	body := mustJSON(t, map[string]string{
		"target": "https://peer.example",
		"id":     "run-1",
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/start", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.HandleStart(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestHandleStart_CreateThenStop(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()
	now := time.Now().Unix()

	runID := "run-stop-flow"
	row := &validatorcore.TestRun{
		TestRunID:   runID,
		State:       validatorcore.StatePassiveComplete,
		SessionKind: validatorcore.SessionKindPassiveOnly,
		TargetHost:  "peer.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := store.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed passive_complete: %v", err)
	}

	stopBody := mustJSON(t, map[string]string{"id": runID})

	stopReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/stop", bytes.NewReader(stopBody))
	stopRec := httptest.NewRecorder()
	h.HandleStop(stopRec, stopReq)

	if stopRec.Code != http.StatusOK {
		t.Fatalf("stop status = %d, want 200", stopRec.Code)
	}
}

func TestHandleStart_CreateSessionReturnsID(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	createBody := mustJSON(t, map[string]string{"target": "https://peer.example"})

	createReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/start", bytes.NewReader(createBody))
	createRec := httptest.NewRecorder()
	h.HandleStart(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201", createRec.Code)
	}

	var created startCreateResponse
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	if created.ID == "" {
		t.Fatal("expected non-empty session id")
	}
}

func TestHandleStop_SessionNotReady(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()
	now := time.Now().Unix()

	runID := "run-not-ready"
	row := &validatorcore.TestRun{
		TestRunID:   runID,
		State:       validatorcore.StateCreated,
		SessionKind: validatorcore.SessionKindPassiveOnly,
		TargetHost:  "peer.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := store.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := mustJSON(t, map[string]string{"id": runID})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/stop", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleStop(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != validatorcore.CodeSessionNotReady {
		t.Fatalf("error code = %q, want %q", payload["error"], validatorcore.CodeSessionNotReady)
	}
}

func TestHandleStop_ActivePassiveCompleteReturnsSessionNotReady(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()
	now := time.Now().Unix()

	runID := "run-active-pc-stop"
	row := &validatorcore.TestRun{
		TestRunID:   runID,
		IsActive:    true,
		State:       validatorcore.StatePassiveComplete,
		SessionKind: validatorcore.SessionKindPassiveOnly,
		TargetHost:  "peer.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := store.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := mustJSON(t, map[string]string{"id": runID})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/stop", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleStop(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != validatorcore.CodeSessionNotReady {
		t.Fatalf("error code = %q, want %q", payload["error"], validatorcore.CodeSessionNotReady)
	}

	if payload["error"] == validatorcore.CodeInteractiveRunInProgress {
		t.Fatalf("stop on active passive_complete must not return %q", validatorcore.CodeInteractiveRunInProgress)
	}
}

func TestHandleStart_ExtendTerminalStateReturnsSessionNotReady(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()
	now := time.Now().Unix()

	runID := "run-extend-terminal"
	row := &validatorcore.TestRun{
		TestRunID:   runID,
		State:       validatorcore.StateTerminalPass,
		SessionKind: validatorcore.SessionKindPassiveOnly,
		TargetHost:  "peer.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := store.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := mustJSON(t, map[string]string{"id": runID})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/start", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleStart(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("extend status = %d, want 409", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != validatorcore.CodeSessionNotReady {
		t.Fatalf("error code = %q, want %q", payload["error"], validatorcore.CodeSessionNotReady)
	}

	if payload["error"] == validatorcore.CodeStopSessionMiss {
		t.Fatalf("extend on terminal state must not return %q", validatorcore.CodeStopSessionMiss)
	}
}

func TestHandleStart_ExtendInteractiveConflict(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()
	now := time.Now().Unix()

	for _, id := range []string{"run-a", "run-b"} {
		row := &validatorcore.TestRun{
			TestRunID:   id,
			State:       validatorcore.StatePassiveComplete,
			SessionKind: validatorcore.SessionKindPassiveOnly,
			TargetHost:  "peer.example",
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		if err := store.DB().WithContext(ctx).Create(row).Error; err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	firstBody := mustJSON(t, map[string]string{"id": "run-a"})

	firstReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/start", bytes.NewReader(firstBody))
	firstRec := httptest.NewRecorder()
	h.HandleStart(firstRec, firstReq)

	if firstRec.Code != http.StatusOK {
		t.Fatalf("first extend status = %d, want 200", firstRec.Code)
	}

	secondBody := mustJSON(t, map[string]string{"id": "run-b"})

	secondReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/start", bytes.NewReader(secondBody))
	secondRec := httptest.NewRecorder()
	h.HandleStart(secondRec, secondReq)

	if secondRec.Code != http.StatusConflict {
		t.Fatalf("second extend status = %d, want 409", secondRec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(secondRec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != validatorcore.CodeInteractiveRunInProgress {
		t.Fatalf("error code = %q, want %q", payload["error"], validatorcore.CodeInteractiveRunInProgress)
	}
}

func TestHandleStart_RepeatedExtendReturnsInteractiveConflict(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-repeat"

	row := &validatorcore.TestRun{
		TestRunID:   runID,
		State:       validatorcore.StatePassiveComplete,
		SessionKind: validatorcore.SessionKindPassiveOnly,
		TargetHost:  "peer.example",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := store.DB().WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	firstBody := mustJSON(t, map[string]string{"id": runID})

	firstReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/start", bytes.NewReader(firstBody))
	firstRec := httptest.NewRecorder()
	h.HandleStart(firstRec, firstReq)

	if firstRec.Code != http.StatusOK {
		t.Fatalf("first extend status = %d, want 200", firstRec.Code)
	}

	secondBody := mustJSON(t, map[string]string{"id": runID})

	secondReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/start", bytes.NewReader(secondBody))
	secondRec := httptest.NewRecorder()
	h.HandleStart(secondRec, secondReq)

	if secondRec.Code != http.StatusConflict {
		t.Fatalf("repeat extend status = %d, want 409", secondRec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(secondRec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != validatorcore.CodeInteractiveRunInProgress {
		t.Fatalf("error code = %q, want %q", payload["error"], validatorcore.CodeInteractiveRunInProgress)
	}
}

func TestCreateSessionRouteSpec_IncludesStop(t *testing.T) {
	t.Parallel()

	stop := StopSessionRouteSpec()
	if stop.Pattern != RouteStopSession {
		t.Fatalf("stop pattern = %q, want %q", stop.Pattern, RouteStopSession)
	}
}

func TestParseTarget(t *testing.T) {
	t.Parallel()

	origin, host, err := parseTarget("https://Peer.Example:443/path")
	if err != nil {
		t.Fatalf("parseTarget: %v", err)
	}

	if origin != "https://Peer.Example:443" {
		t.Fatalf("origin = %q", origin)
	}

	if host != "peer.example" {
		t.Fatalf("host = %q", host)
	}

	if _, _, parseErr := parseTarget("not-a-url"); parseErr == nil {
		t.Fatal("expected parse error for invalid target")
	}
}

func TestHandleScan_ContributeOptInPersistsOnStop(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()

	createReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"/api/scan?target=https://peer.example&contribute=1",
		nil,
	)
	createRec := httptest.NewRecorder()
	h.HandleScan(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("scan status = %d, want 201", createRec.Code)
	}

	var created startCreateResponse
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	if created.ID == "" {
		t.Fatal("expected non-empty session id")
	}

	waitForState(t, store, ctx, created.ID, validatorcore.StatePassiveComplete)

	stopBody := mustJSON(t, map[string]string{"id": created.ID})

	stopReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/stop", bytes.NewReader(stopBody))
	stopRec := httptest.NewRecorder()
	h.HandleStop(stopRec, stopReq)

	if stopRec.Code != http.StatusOK {
		t.Fatalf("stop status = %d, want 200", stopRec.Code)
	}

	var rawCount int64
	if err := store.DB().WithContext(ctx).Model(&validatorcore.StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 1 {
		t.Fatalf("stats_raw count = %d, want 1", rawCount)
	}

	var raw validatorcore.StatsRaw
	if err := store.DB().WithContext(ctx).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if strings.Contains(raw.HostHash, "peer.example") {
		t.Fatalf("host_hash must not contain raw host, got %q", raw.HostHash)
	}
}

func TestHandleScan_IncognitoDoesNotPersistOnStop(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()

	createReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"/api/scan?target=https://peer.example&contribute=0",
		nil,
	)
	createRec := httptest.NewRecorder()
	h.HandleScan(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("scan status = %d, want 201", createRec.Code)
	}

	var created startCreateResponse
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	waitForState(t, store, ctx, created.ID, validatorcore.StatePassiveComplete)

	stopBody := mustJSON(t, map[string]string{"id": created.ID})

	stopReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/stop", bytes.NewReader(stopBody))
	stopRec := httptest.NewRecorder()
	h.HandleStop(stopRec, stopReq)

	if stopRec.Code != http.StatusOK {
		t.Fatalf("stop status = %d, want 200", stopRec.Code)
	}

	var rawCount int64
	if err := store.DB().WithContext(ctx).Model(&validatorcore.StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 0 {
		t.Fatalf("stats_raw count = %d, want 0", rawCount)
	}
}

func TestHandleStart_DoesNotOptInStatistics(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	ctx := t.Context()

	createBody := mustJSON(t, map[string]string{"target": "https://peer.example"})

	createReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/start", bytes.NewReader(createBody))
	createRec := httptest.NewRecorder()
	h.HandleStart(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201", createRec.Code)
	}

	var created startCreateResponse
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	waitForState(t, store, ctx, created.ID, validatorcore.StatePassiveComplete)

	stopBody := mustJSON(t, map[string]string{"id": created.ID})

	stopReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/stop", bytes.NewReader(stopBody))
	stopRec := httptest.NewRecorder()
	h.HandleStop(stopRec, stopReq)

	if stopRec.Code != http.StatusOK {
		t.Fatalf("stop status = %d, want 200", stopRec.Code)
	}

	var rawCount int64
	if err := store.DB().WithContext(ctx).Model(&validatorcore.StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != 0 {
		t.Fatalf("stats_raw count = %d, want 0 for POST /start default incognito", rawCount)
	}
}

func TestWriteJSON_EncodeFailureDoesNotWriteResponse(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	writeJSON(rec, nil, http.StatusOK, make(chan int))

	if rec.Body.Len() != 0 {
		t.Fatalf("body length = %d, want 0 on encode failure", rec.Body.Len())
	}

	if ct := rec.Header().Get("Content-Type"); ct != "" {
		t.Fatalf("content-type = %q, want empty (headers not committed)", ct)
	}
}

func TestWriteJSON_SuccessWritesOnce(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	writeJSON(rec, nil, http.StatusOK, map[string]string{"id": "run-1"})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["id"] != "run-1" {
		t.Fatalf("id = %q, want run-1", payload["id"])
	}
}
