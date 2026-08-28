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
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestHandleScan_PersistsTypedOCMID(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)

	createReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"/api/scan?target=mahdi@ponder.org",
		nil,
	)
	createRec := httptest.NewRecorder()
	h.HandleScan(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("scan status = %d, want 201 body %s", createRec.Code, createRec.Body.String())
	}

	row := loadCreatedRun(t, store, createRec)
	if row.TargetOrigin != "https://ponder.org" {
		t.Fatalf("TargetOrigin = %q, want https://ponder.org", row.TargetOrigin)
	}

	if row.TargetHost != "ponder.org" {
		t.Fatalf("TargetHost = %q, want ponder.org", row.TargetHost)
	}

	if row.RemoteOCMID == nil || *row.RemoteOCMID != "mahdi@ponder.org" {
		t.Fatalf("RemoteOCMID = %v, want mahdi@ponder.org", row.RemoteOCMID)
	}
}

func TestHandleScan_URLLeavesRemoteOCMIDNull(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)

	createReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"/api/scan?target=https://peer.example:8443",
		nil,
	)
	createRec := httptest.NewRecorder()
	h.HandleScan(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("scan status = %d, want 201 body %s", createRec.Code, createRec.Body.String())
	}

	row := loadCreatedRun(t, store, createRec)
	if row.TargetOrigin != "https://peer.example:8443" {
		t.Fatalf("TargetOrigin = %q, want https://peer.example:8443", row.TargetOrigin)
	}

	if row.TargetHost != "peer.example:8443" {
		t.Fatalf("TargetHost = %q, want peer.example:8443", row.TargetHost)
	}

	if row.RemoteOCMID != nil {
		t.Fatalf("RemoteOCMID = %v, want nil", row.RemoteOCMID)
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
