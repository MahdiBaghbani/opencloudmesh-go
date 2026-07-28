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
	//nolint:errcheck // response already started; write error cannot be recovered
	json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
}
