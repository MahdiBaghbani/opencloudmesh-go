// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// ocmgo:file-length-ignore: passive handler lifecycle, scan consent, and session route integration coverage

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

func waitForState(t *testing.T, store *validatorcore.Core, ctx context.Context, runID string) {
	t.Helper()

	const wantState = validatorcore.StatePassiveComplete

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
		TestRunID:  runID,
		State:      validatorcore.StatePassiveComplete,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now,
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
		TestRunID:  runID,
		State:      validatorcore.StateCreated,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now,
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
		TestRunID:  runID,
		IsActive:   true,
		State:      validatorcore.StatePassiveComplete,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now,
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

func TestHandleStart_IDOnlyIsRejected(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)
	body := mustJSON(t, map[string]string{"id": "run-old-extend"})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/start", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleStart(rec, req)

	assertJSONError(t, rec, "invalid_request")
}

func TestCreateSessionRouteSpec_IncludesStop(t *testing.T) {
	t.Parallel()

	stop := StopSessionRouteSpec()
	if stop.Pattern != RouteStopSession {
		t.Fatalf("stop pattern = %q, want %q", stop.Pattern, RouteStopSession)
	}
}

func TestHandleStart_PersistsTypedOCMID(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)

	createReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/start",
		bytes.NewReader(mustJSON(t, map[string]string{"target": "mahdi@ponder.org"})),
	)
	createRec := httptest.NewRecorder()
	h.HandleStart(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201 body %s", createRec.Code, createRec.Body.String())
	}

	row := loadCreatedRun(t, store, createRec)
	if row.TargetOrigin != "https://ponder.org" {
		t.Fatalf("TargetOrigin = %q, want https://ponder.org", row.TargetOrigin)
	}

	if row.TargetHost != "ponder.org" {
		t.Fatalf("TargetHost = %q, want ponder.org", row.TargetHost)
	}

	if row.StarterOCMID == nil || *row.StarterOCMID != "mahdi@ponder.org" {
		t.Fatalf("StarterOCMID = %v, want mahdi@ponder.org", row.StarterOCMID)
	}
}

func TestHandleStart_URLLeavesStarterOCMIDNull(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)

	createReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/start",
		bytes.NewReader(mustJSON(t, map[string]string{"target": "https://peer.example:8443"})),
	)
	createRec := httptest.NewRecorder()
	h.HandleStart(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201 body %s", createRec.Code, createRec.Body.String())
	}

	row := loadCreatedRun(t, store, createRec)
	if row.TargetOrigin != "https://peer.example:8443" {
		t.Fatalf("TargetOrigin = %q, want https://peer.example:8443", row.TargetOrigin)
	}

	if row.TargetHost != "peer.example:8443" {
		t.Fatalf("TargetHost = %q, want peer.example:8443", row.TargetHost)
	}

	if row.StarterOCMID != nil {
		t.Fatalf("StarterOCMID = %v, want nil", row.StarterOCMID)
	}
}

func TestHandleStart_RejectsURLUserinfo(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)
	createReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/start",
		bytes.NewReader(mustJSON(t, map[string]string{"target": "https://alice@peer.example"})),
	)
	createRec := httptest.NewRecorder()
	h.HandleStart(createRec, createReq)

	assertJSONError(t, createRec, "invalid_request")
	assertBodyOmitsSecrets(t, createRec.Body.String(), "https://alice@peer.example")
}

func TestHandleStart_MalformedURLUserinfoDoesNotEchoSecrets(t *testing.T) {
	t.Parallel()

	const raw = "https://alice:secret@[::1"

	h := NewHandler(openHandlerTestStore(t), nil)
	createReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/start",
		bytes.NewReader(mustJSON(t, map[string]string{"target": raw})),
	)
	createRec := httptest.NewRecorder()
	h.HandleStart(createRec, createReq)

	if createRec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body %s", createRec.Code, createRec.Body.String())
	}

	body := createRec.Body.String()
	assertBodyOmitsSecrets(t, body, raw)

	var payload map[string]string
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&payload); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if payload["error"] != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", payload["error"])
	}

	if payload["message"] != errInvalidTarget.Error() {
		t.Fatalf("message = %q, want %q", payload["message"], errInvalidTarget.Error())
	}

	okURL := httptest.NewRecorder()
	h.HandleStart(
		okURL,
		httptest.NewRequestWithContext(
			t.Context(),
			http.MethodPost,
			"/start",
			bytes.NewReader(mustJSON(t, map[string]string{"target": "https://peer.example:8443"})),
		),
	)

	if okURL.Code != http.StatusCreated {
		t.Fatalf("https URL status = %d, want 201 body %s", okURL.Code, okURL.Body.String())
	}

	okOCM := httptest.NewRecorder()
	h.HandleStart(
		okOCM,
		httptest.NewRequestWithContext(
			t.Context(),
			http.MethodPost,
			"/start",
			bytes.NewReader(mustJSON(t, map[string]string{"target": "mahdi@ponder.org"})),
		),
	)

	if okOCM.Code != http.StatusCreated {
		t.Fatalf("OCM id status = %d, want 201 body %s", okOCM.Code, okOCM.Body.String())
	}
}

func assertBodyOmitsSecrets(t *testing.T, body, raw string) {
	t.Helper()

	for _, leak := range []string{"secret", "alice", raw} {
		if leak != "" && strings.Contains(body, leak) {
			t.Fatalf("response leaked %q: %s", leak, body)
		}
	}
}

func loadCreatedRun(
	t *testing.T,
	store *validatorcore.Core,
	rec *httptest.ResponseRecorder,
) *validatorcore.TestRun {
	t.Helper()

	created := decodeCreateEcho(t, rec)

	row, err := store.GetTestRun(t.Context(), created.ID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	return row
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

	waitForState(t, store, ctx, created.ID)

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

	waitForState(t, store, ctx, created.ID)

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

	waitForState(t, store, ctx, created.ID)

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
