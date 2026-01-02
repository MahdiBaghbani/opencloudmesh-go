package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/discovery"
)

// AuxHandler serves the /ocm-aux endpoints.
type AuxHandler struct {
	federationMgr   *FederationManager
	discoveryClient *discovery.Client
}

// NewAuxHandler creates a new auxiliary handler.
func NewAuxHandler(fedMgr *FederationManager, discClient *discovery.Client) *AuxHandler {
	return &AuxHandler{
		federationMgr:   fedMgr,
		discoveryClient: discClient,
	}
}

// FederationsResponse is the response for GET /ocm-aux/federations.
type FederationsResponse struct {
	Federations []FederationInfo `json:"federations"`
	Members     []MemberInfo     `json:"members"`
}

// FederationInfo describes a federation.
type FederationInfo struct {
	FederationID      string `json:"federation_id"`
	Enabled           bool   `json:"enabled"`
	EnforceMembership bool   `json:"enforce_membership"`
	MemberCount       int    `json:"member_count"`
}

// MemberInfo describes a federation member.
type MemberInfo struct {
	Host         string `json:"host"`
	Name         string `json:"name,omitempty"`
	FederationID string `json:"federation_id"`
}

// HandleFederations handles GET /ocm-aux/federations.
func (h *AuxHandler) HandleFederations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	response := FederationsResponse{
		Federations: []FederationInfo{},
		Members:     []MemberInfo{},
	}

	if h.federationMgr != nil {
		// Get federations
		for _, fed := range h.federationMgr.GetFederations() {
			response.Federations = append(response.Federations, FederationInfo{
				FederationID:      fed.FederationID,
				Enabled:           fed.Enabled,
				EnforceMembership: fed.EnforceMembership,
			})
		}

		// Get all members
		allMembers := h.federationMgr.GetAllMembers(ctx)
		for _, m := range allMembers {
			response.Members = append(response.Members, MemberInfo{
				Host: m.Host,
				Name: m.Name,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// DiscoverRequest is the request for GET /ocm-aux/discover.
type DiscoverRequest struct {
	BaseURL string `json:"base_url"`
}

// DiscoverResponse is the response for GET /ocm-aux/discover.
type DiscoverResponse struct {
	Success   bool               `json:"success"`
	Error     string             `json:"error,omitempty"`
	Discovery *discovery.Discovery `json:"discovery,omitempty"`
}

// HandleDiscover handles GET /ocm-aux/discover.
// Query param: base=<url>
func (h *AuxHandler) HandleDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	baseURL := r.URL.Query().Get("base")
	if baseURL == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(DiscoverResponse{
			Success: false,
			Error:   "missing 'base' query parameter",
		})
		return
	}

	// Normalize URL
	baseURL = strings.TrimSuffix(baseURL, "/")

	// Fetch discovery
	disc, err := h.discoveryClient.Discover(context.Background(), baseURL)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(DiscoverResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DiscoverResponse{
		Success:   true,
		Discovery: disc,
	})
}
