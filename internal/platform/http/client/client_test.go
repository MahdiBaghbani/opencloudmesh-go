// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package client_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	outboundtestutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestClient_DoPreservesInterface(t *testing.T) {
	t.Parallel()

	// Verify Do() still works with the standard http.Request interface

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := outboundtestutil.NewPermissive(nil)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := client.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("Do() failed: %v", err)
	}
	defer outboundtestutil.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}
