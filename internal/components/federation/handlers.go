package federation

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
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
// Returns:
//   - 400: missing/invalid base (parse error, unsupported scheme, missing host)
//   - 403: SSRF blocked target
//   - 501: discovery client not configured
//   - 502: upstream/network/discovery failure
func (h *AuxHandler) HandleDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context() // Use request context for cancellation propagation

	baseParam := r.URL.Query().Get("base")
	if baseParam == "" {
		h.sendDiscoverError(w, http.StatusBadRequest, "missing 'base' query parameter")
		return
	}

	// Parse and normalize to origin (<scheme>://<host>)
	originURL, err := normalizeToOrigin(baseParam)
	if err != nil {
		h.sendDiscoverError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Check if discovery client is configured
	if h.discoveryClient == nil {
		h.sendDiscoverError(w, http.StatusNotImplemented, "discovery client not configured")
		return
	}

	// Fetch discovery using request context
	disc, err := h.discoveryClient.Discover(ctx, originURL)
	if err != nil {
		// Classify error for status mapping
		if httpclient.IsSSRFError(err) {
			h.sendDiscoverError(w, http.StatusForbidden, err.Error())
			return
		}
		// All other errors are upstream failures
		h.sendDiscoverError(w, http.StatusBadGateway, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DiscoverResponse{
		Success:   true,
		Discovery: disc,
	})
}

// sendDiscoverError sends a JSON error response for the discover endpoint.
func (h *AuxHandler) sendDiscoverError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(DiscoverResponse{
		Success: false,
		Error:   message,
	})
}

// normalizeToOrigin parses a URL and returns just the origin (<scheme>://<host>).
// Accepts URLs with path/query/fragment but normalizes to origin only.
// Requires http or https scheme and non-empty host.
func normalizeToOrigin(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	// Validate scheme
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", &url.Error{Op: "parse", URL: rawURL, Err: errUnsupportedScheme}
	}

	// Validate host
	if parsed.Host == "" {
		return "", &url.Error{Op: "parse", URL: rawURL, Err: errMissingHost}
	}

	// Return origin only
	return scheme + "://" + parsed.Host, nil
}

// Sentinel errors for URL validation
type validationError string

func (e validationError) Error() string { return string(e) }

const (
	errUnsupportedScheme = validationError("unsupported scheme: must be http or https")
	errMissingHost       = validationError("missing host")
)
