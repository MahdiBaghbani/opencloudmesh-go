// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/healthz", nil)
	w := httptest.NewRecorder()

	HealthHandler(w, req)

	res := w.Result()
	defer tshttp.MustClose(t, res.Body)

	if res.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", res.StatusCode)
	}

	contentType := res.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	var resp HealthResponse
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", resp.Status)
	}
}
