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
