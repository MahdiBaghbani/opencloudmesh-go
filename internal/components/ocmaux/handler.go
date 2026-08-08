// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package ocmaux provides /ocm-aux HTTP handlers (federations, discover).
package ocmaux

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// AuxHandler serves the /ocm-aux endpoints.
type AuxHandler struct {
	trustGroupMgr   *peertrust.TrustGroupManager
	discoveryClient *discovery.Client
	logger          *slog.Logger
}

// NewAuxHandler builds an auxiliary handler.
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

// serverEntry is a server in a federation, optionally with discovery-enriched inviteAcceptDialog.
type serverEntry struct {
	DisplayName        string                  `json:"displayName"`
	URL                string                  `json:"url"`
	InviteAcceptDialog string                  `json:"inviteAcceptDialog,omitempty"`
	Status             *serverEnrichmentStatus `json:"status,omitempty"`
}

// serverEnrichmentStatus reports OCM discovery enrichment outcome for a federation row.
type serverEnrichmentStatus struct {
	Discovery  string `json:"discovery"`
	ReasonCode string `json:"reasonCode,omitempty"`
}

const discoveryEnrichmentFailed = "failed"

// HandleFederations serves GET /ocm-aux/federations (Reva-aligned, discovery-enriched).
func (h *AuxHandler) HandleFederations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	ctx := r.Context()

	result := []federationEntry{}

	if h.trustGroupMgr != nil {
		listings := h.trustGroupMgr.GetDirectoryListings(ctx)

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

				if h.discoveryClient != nil {
					disc, err := h.discoveryClient.Discover(ctx, srv.URL)
					if err != nil {
						_, reasonCode, _ := classifyDiscoverError(err)
						if reasonCode == "" {
							reasonCode = reason.PeerDiscoveryFailed
						}

						se.Status = &serverEnrichmentStatus{
							Discovery:  discoveryEnrichmentFailed,
							ReasonCode: reasonCode,
						}
						h.logger.Debug("discovery enrichment failed, keeping server with status",
							"federation", listing.Federation,
							"server_url", srv.URL,
							"reason_code", reasonCode,
							"error", err,
						)
					} else if disc.InviteAcceptDialog != "" {
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

	if err := json.NewEncoder(w).Encode(result); err != nil {
		h.logger.Error("failed to encode federations", "error", err)
	}
}

// resolveInviteDialog resolves relative inviteAcceptDialog against server URL.
func resolveInviteDialog(serverURL, dialog string) string {
	if dialog == "" {
		return ""
	}

	if strings.HasPrefix(dialog, "http://") || strings.HasPrefix(dialog, "https://") {
		return dialog
	}

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

// DiscoverResponse is the JSON response for /ocm-aux/discover.
type DiscoverResponse struct {
	Success                    bool            `json:"success"`
	Error                      string          `json:"error,omitempty"`
	ReasonCode                 string          `json:"reasonCode,omitempty"`
	Discovery                  *spec.Discovery `json:"discovery,omitempty"`
	InviteAcceptDialogAbsolute string          `json:"inviteAcceptDialogAbsolute,omitempty"`
}

// Discover reason codes for /ocm-aux/discover helper responses.
const (
	discoverReasonInvalidURL           = "invalid_url"
	discoverReasonDNSUnresolvable      = "dns_unresolvable"
	discoverReasonNoOCMDiscovery       = "no_ocm_discovery"
	discoverReasonNoInviteAcceptDialog = "no_invite_accept_dialog"
)

const (
	discoverMsgMissingBase          = "Enter a provider URL to discover."
	discoverMsgInvalidURL           = "Enter a valid provider URL using http or https."
	discoverMsgSSRFBlocked          = "That provider address is not allowed."
	discoverMsgDNSFailed            = "Could not resolve that provider address."
	discoverMsgNoOCM                = "No OCM-enabled provider was found at that address."
	discoverMsgNoInviteAcceptDialog = "That provider does not provide an invite accept dialog."
	discoverMsgUpstream             = "Could not reach that provider."
)

// HandleDiscover serves GET /ocm-aux/discover?base=<url>. Returns 400/403/501/502 on error.
func (h *AuxHandler) HandleDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	ctx := r.Context()

	baseParam := strings.TrimSpace(r.URL.Query().Get("base"))
	if baseParam == "" {
		h.sendDiscoverError(w, http.StatusBadRequest, discoverMsgMissingBase, discoverReasonInvalidURL, nil)

		return
	}

	originURL, normErr := normalizeToOrigin(baseParam)
	if normErr != nil {
		h.sendDiscoverError(w, http.StatusBadRequest, discoverMsgInvalidURL, discoverReasonInvalidURL, normErr)

		return
	}

	if h.discoveryClient == nil {
		h.sendDiscoverError(w, http.StatusNotImplemented, "discovery client not configured", reason.PeerDiscoveryDisabled, nil)

		return
	}

	disc, err := h.discoveryClient.Discover(ctx, originURL)
	if err != nil {
		status, reasonCode, userMsg := classifyDiscoverError(err)
		h.sendDiscoverError(w, status, userMsg, reasonCode, err)

		return
	}

	if disc.InviteAcceptDialog == "" {
		h.sendDiscoverError(w, http.StatusBadGateway, discoverMsgNoInviteAcceptDialog, discoverReasonNoInviteAcceptDialog, nil)

		return
	}

	resp := DiscoverResponse{
		Success:                    true,
		Discovery:                  disc,
		InviteAcceptDialogAbsolute: resolveInviteDialog(originURL, disc.InviteAcceptDialog),
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("failed to encode discover response", "error", err)
	}
}

// sendDiscoverError returns a JSON error for the discover endpoint.
func (h *AuxHandler) sendDiscoverError(w http.ResponseWriter, status int, message, reasonCode string, debugErr error) {
	if debugErr != nil {
		h.logger.Debug("ocm-aux discover failed",
			"reason_code", reasonCode,
			"error", debugErr,
		)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := DiscoverResponse{
		Success: false,
		Error:   message,
	}
	if reasonCode != "" {
		resp.ReasonCode = reasonCode
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("failed to encode discover error", "error", err)
	}
}

// normalizeToOrigin normalizes user-entered provider input to scheme://host[:port].
func normalizeToOrigin(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", errMissingHost
	}

	candidate := rawURL
	if !strings.Contains(candidate, "://") {
		candidate = "https://" + candidate
	}

	parsed, err := url.Parse(candidate)
	if err != nil {
		return "", fmt.Errorf("ocmaux: normalize provider origin: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errUnsupportedScheme
	}

	host := parsed.Host
	if host == "" {
		// Bare host without path can land in Path when scheme is missing from input.
		if parsed.Path != "" && !strings.Contains(parsed.Path, "/") && !strings.Contains(parsed.Path, ":") {
			host = parsed.Path
		}
	}

	if host == "" {
		return "", errMissingHost
	}

	return scheme + "://" + host, nil
}

func classifyDiscoverError(err error) (status int, reasonCode, userMsg string) {
	if err == nil {
		return http.StatusOK, "", ""
	}

	if httpclient.IsSSRFError(err) {
		return http.StatusForbidden, reason.SSRFBlocked, discoverMsgSSRFBlocked
	}

	if httpclient.IsHostUnresolvable(err) {
		return http.StatusBadGateway, discoverReasonDNSUnresolvable, discoverMsgDNSFailed
	}

	if errors.Is(err, httpclient.ErrInvalidURL) {
		return http.StatusBadRequest, discoverReasonInvalidURL, discoverMsgInvalidURL
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return http.StatusBadGateway, reason.PeerUnreachable, discoverMsgUpstream
	}

	if errors.Is(err, discovery.ErrOCMDisabled) ||
		errors.Is(err, discovery.ErrInvalidDiscoveryJSON) ||
		errors.Is(err, discovery.ErrDiscoveryNotFound) {
		return http.StatusBadGateway, discoverReasonNoOCMDiscovery, discoverMsgNoOCM
	}

	return http.StatusBadGateway, reason.PeerDiscoveryFailed, discoverMsgUpstream
}

type validationError string

func (e validationError) Error() string { return string(e) }

const (
	errUnsupportedScheme = validationError("unsupported scheme: must be http or https")
	errMissingHost       = validationError("missing host")
)
