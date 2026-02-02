// Package ocmaux provides auxiliary HTTP handlers for OCM helper endpoints.
package ocmaux

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// AuxHandler serves the /ocm-aux endpoints.
type AuxHandler struct {
	trustGroupMgr   *peertrust.TrustGroupManager
	discoveryClient *discovery.Client
	logger          *slog.Logger
}

// NewAuxHandler creates a new auxiliary handler.
func NewAuxHandler(trustGroupMgr *peertrust.TrustGroupManager, discClient *discovery.Client, logger *slog.Logger) *AuxHandler {
	logger = logutil.NoopIfNil(logger)
	return &AuxHandler{
		trustGroupMgr:   trustGroupMgr,
		discoveryClient: discClient,
		logger:          logger,
	}
}

// federationEntry is a single trust group in the /ocm-aux/federations response (Reva-aligned).
type federationEntry struct {
	Federation string        `json:"federation"`
	Servers    []serverEntry `json:"servers"`
}

// serverEntry is a server within a federation entry, enriched with discovery data.
type serverEntry struct {
	DisplayName        string `json:"displayName"`
	URL                string `json:"url"`
	InviteAcceptDialog string `json:"inviteAcceptDialog,omitempty"`
}

// HandleFederations handles GET /ocm-aux/federations.
// Returns a Reva-aligned JSON array of federation entries with discovery-enriched servers.
func (h *AuxHandler) HandleFederations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// Empty array (not null) when no trust group manager or no listings
	result := []federationEntry{}

	if h.trustGroupMgr != nil {
		listings := h.trustGroupMgr.GetDirectoryListings(ctx)

		// Merge listings by federation name
		merged := make(map[string]*federationEntry)
		var order []string
		for _, listing := range listings {
			entry, exists := merged[listing.Federation]
			if !exists {
				entry = &federationEntry{Federation: listing.Federation}
				merged[listing.Federation] = entry
				order = append(order, listing.Federation)
			}
			for _, srv := range listing.Servers {
				se := serverEntry{
					DisplayName: srv.DisplayName,
					URL:         srv.URL,
				}

				// Enrich with discovery data (inviteAcceptDialog)
				if h.discoveryClient != nil {
					disc, err := h.discoveryClient.Discover(ctx, srv.URL)
					if err != nil {
						h.logger.Debug("discovery enrichment failed, dropping server",
							"federation", listing.Federation,
							"server_url", srv.URL,
							"error", err,
						)
						continue // silently drop this server
					}
					if disc.InviteAcceptDialog != "" {
						se.InviteAcceptDialog = resolveInviteDialog(srv.URL, disc.InviteAcceptDialog)
					}
				}

				entry.Servers = append(entry.Servers, se)
			}
		}

		for _, name := range order {
			entry := merged[name]
			if entry.Servers == nil {
				entry.Servers = []serverEntry{}
			}
			result = append(result, *entry)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// resolveInviteDialog resolves a potentially relative inviteAcceptDialog URL against the server URL.
func resolveInviteDialog(serverURL, dialog string) string {
	if dialog == "" {
		return ""
	}
	// If already absolute, return as-is
	if strings.HasPrefix(dialog, "http://") || strings.HasPrefix(dialog, "https://") {
		return dialog
	}
	// Resolve relative against server URL
	base, err := url.Parse(serverURL)
	if err != nil {
		return dialog
	}
	ref, err := url.Parse(dialog)
	if err != nil {
		return dialog
	}
	return base.ResolveReference(ref).String()
}

// DiscoverResponse is the response for GET /ocm-aux/discover.
type DiscoverResponse struct {
	Success                    bool                 `json:"success"`
	Error                      string               `json:"error,omitempty"`
	Discovery                  *discovery.Discovery `json:"discovery,omitempty"`
	InviteAcceptDialogAbsolute string               `json:"inviteAcceptDialogAbsolute,omitempty"`
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

	ctx := r.Context()

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

	if h.discoveryClient == nil {
		h.sendDiscoverError(w, http.StatusNotImplemented, "discovery client not configured")
		return
	}

	disc, err := h.discoveryClient.Discover(ctx, originURL)
	if err != nil {
		if httpclient.IsSSRFError(err) {
			h.sendDiscoverError(w, http.StatusForbidden, err.Error())
			return
		}
		h.sendDiscoverError(w, http.StatusBadGateway, err.Error())
		return
	}

	resp := DiscoverResponse{
		Success:   true,
		Discovery: disc,
	}

	// Resolve inviteAcceptDialog to an absolute URL for WAYF consumers
	if disc.InviteAcceptDialog != "" {
		resp.InviteAcceptDialogAbsolute = resolveInviteDialog(originURL, disc.InviteAcceptDialog)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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
func normalizeToOrigin(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", &url.Error{Op: "parse", URL: rawURL, Err: errUnsupportedScheme}
	}

	if parsed.Host == "" {
		return "", &url.Error{Op: "parse", URL: rawURL, Err: errMissingHost}
	}

	return scheme + "://" + parsed.Host, nil
}

type validationError string

func (e validationError) Error() string { return string(e) }

const (
	errUnsupportedScheme = validationError("unsupported scheme: must be http or https")
	errMissingHost       = validationError("missing host")
)
