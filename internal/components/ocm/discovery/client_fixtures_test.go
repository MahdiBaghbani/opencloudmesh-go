// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func validDiscoveryPayload(serverURL string, extra map[string]any) map[string]any {
	endpoint := strings.TrimSuffix(serverURL, "/") + "/ocm"

	raw := map[string]any{
		"enabled":       true,
		"apiVersion":    "1.4.0",
		"endPoint":      endpoint,
		"resourceTypes": []any{},
		"criteria":      []any{},
	}
	for k, v := range extra {
		raw[k] = v
	}

	return raw
}

func newDiscoveryTestServer(t *testing.T, handler func(serverURL string, w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()

	var srv *httptest.Server

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(srv.URL, w, r)
	}))
	t.Cleanup(srv.Close)

	return srv
}

func hasDiffersFromPinWarning(warnings []string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "differs from pin") {
			return true
		}
	}

	return false
}
