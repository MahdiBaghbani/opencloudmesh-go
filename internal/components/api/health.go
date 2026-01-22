// Package api provides auxiliary JSON API handlers.
package api

import (
	"encoding/json"
	"net/http"
)

// HealthResponse is the response for the health endpoint.
type HealthResponse struct {
	Status string `json:"status"`
}

// HealthHandler handles GET /api/healthz requests.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
}
