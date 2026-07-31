// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package api

import (
	"encoding/json"
	"net/http"
)

// HealthResponse is the body of the health check endpoint.
type HealthResponse struct {
	Status string `json:"status"`
}

// HealthHandler handles GET /api/healthz.
func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	//nolint:errcheck,errchkjson // response already started; write error cannot be recovered; payload marshals to fixed JSON, so encode failure is always nil in practice
	json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
}
