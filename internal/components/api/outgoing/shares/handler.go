// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package shares provides the session-gated handler for POST /api/shares/outgoing (create shares to remote receivers).
package shares

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	ocmshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// PeerFactsResolver resolves code-flow facts for a remote peer.
type PeerFactsResolver interface {
	ResolveFacts(host string) policy.Facts
}

// Handler serves POST /api/shares/outgoing to create and send shares.
type Handler struct {
	repo               sharesoutgoing.OutgoingShareRepo
	discoveryClient    *discovery.Client
	httpClient         httpclient.HTTPClient
	signer             *crypto.RFC9421Signer
	peerOrigin         *peerorigin.Resolver
	resolver           PeerFactsResolver
	localProvider      string // raw host[:port] for owner/sender identity
	localTokenEndPoint string
	currentUser        func(context.Context) (*identity.User, error)
	logger             *slog.Logger
	allowedPaths       []string
}

// NewHandler returns a Handler with the given dependencies. Panics if discoveryClient is nil.
func NewHandler(
	repo sharesoutgoing.OutgoingShareRepo,
	discClient *discovery.Client,
	httpClient httpclient.HTTPClient,
	signer *crypto.RFC9421Signer,
	localProvider string,
	currentUser func(context.Context) (*identity.User, error),
	logger *slog.Logger,
	resolver PeerFactsResolver,
	localTokenEndPoint string,
) *Handler {
	if discClient == nil {
		panic("outgoingshares.NewHandler: discoveryClient must not be nil")
	}

	logger = logutil.NoopIfNil(logger)

	return &Handler{
		repo:               repo,
		discoveryClient:    discClient,
		httpClient:         httpClient,
		signer:             signer,
		localProvider:      localProvider,
		localTokenEndPoint: localTokenEndPoint,
		currentUser:        currentUser,
		logger:             logger,
		resolver:           resolver,
	}
}

// SetAllowedPaths restricts localPath to the given directory prefixes.
func (h *Handler) SetAllowedPaths(paths []string) {
	h.allowedPaths = paths
}

// SetPeerOrigin wires the peer origin resolver used for receiver discovery.
func (h *Handler) SetPeerOrigin(peerOrigin *peerorigin.Resolver) {
	h.peerOrigin = peerOrigin
}

// HandleCreate handles POST /api/shares/outgoing.
func (h *Handler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	req, user, ok := h.parseOutgoingRequest(w, r)
	if !ok {
		return
	}

	cleanPath, resourceType, name, ok := h.resolveLocalResource(w, r, req)
	if !ok {
		return
	}

	providerID, webdavID, sharedSecret, ok := h.generateShareIdentifiers(w, r)
	if !ok {
		return
	}

	origin, disc, requirements, ok := h.resolveReceiverAndRequirements(w, r, req)
	if !ok {
		return
	}

	webdavURI, ok := h.buildWebDAVURI(w, r, req, webdavID, disc)
	if !ok {
		return
	}

	owner := address.FormatOutgoingOCMAddressFromUserID(user.ID, h.localProvider)
	sender := address.FormatOutgoingOCMAddressFromUserID(user.ID, h.localProvider)

	webdavProto := &spec.WebDAVProtocol{
		URI:          webdavURI,
		SharedSecret: sharedSecret,
		Permissions:  req.Permissions,
		Requirements: requirements,
	}

	payload := spec.NewShareRequest{
		ShareWith:    req.ShareWith,
		Name:         name,
		ProviderID:   providerID.String(),
		Owner:        owner,
		Sender:       sender,
		ShareType:    "user",
		ResourceType: resourceType,
		Protocol: spec.Protocol{
			Name:   "multi",
			WebDAV: webdavProto,
		},
	}

	if err := h.sendShareToReceiver(r.Context(), origin, disc, payload); err != nil {
		h.logger.Warn("failed to deliver share to receiver", "receiver", req.ReceiverDomain, "error", err)
		api.WriteError(w, http.StatusBadGateway, reason.PeerUnreachable, "failed to deliver share to receiver")

		return
	}

	now := time.Now()
	share := &sharesoutgoing.OutgoingShare{
		ProviderID:       providerID.String(),
		WebDAVID:         webdavID.String(),
		SharedSecret:     sharedSecret,
		LocalPath:        cleanPath,
		ReceiverHost:     origin.peerDomain,
		ReceiverEndPoint: disc.EndPoint,
		ShareWith:        req.ShareWith,
		Name:             name,
		ResourceType:     resourceType,
		ShareType:        "user",
		Permissions:      req.Permissions,
		Owner:            owner,
		Sender:           sender,
		Status:           ocmshares.OutgoingShareStatusSent,
		SentAt:           &now,
		Requirements:     requirements,
	}

	if err := h.repo.Create(r.Context(), share); err != nil {
		h.logger.Error("failed to store outgoing share", "error", err)
		api.WriteInternalError(w, "share sent but local persistence failed")

		return
	}

	h.logger.Info("outgoing share created and sent",
		"share_id", share.ShareID,
		"provider_id", share.ProviderID,
		"receiver", req.ReceiverDomain)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(map[string]string{
		"shareId":    share.ShareID,
		"providerId": share.ProviderID,
		"webdavId":   share.WebDAVID,
		"status":     string(share.Status),
	}); err != nil {
		h.logger.Error("failed to encode share response", "error", err)
	}
}

// validateLocalPath resolves relative paths under the managed content root,
// then ensures the result is under allowedPaths with no traversal.
func (h *Handler) validateLocalPath(path string) (string, error) {
	cleanPath := filepath.Clean(path)

	if strings.Contains(cleanPath, "..") {
		return "", errors.New("path traversal not allowed")
	}

	if !filepath.IsAbs(cleanPath) {
		if len(h.allowedPaths) == 0 {
			return "", errors.New("path not in allowed directories")
		}

		contentRoot := filepath.Clean(h.allowedPaths[0])
		cleanPath = filepath.Clean(filepath.Join(contentRoot, cleanPath))
	}

	if !h.isPathAllowed(cleanPath) {
		return "", errors.New("path not in allowed directories")
	}

	return cleanPath, nil
}

func (h *Handler) isPathAllowed(cleanPath string) bool {
	for _, prefix := range h.allowedPaths {
		cleanPrefix := filepath.Clean(prefix)
		if cleanPrefix == string(os.PathSeparator) {
			if filepath.IsAbs(cleanPath) {
				return true
			}

			continue
		}

		if cleanPath == cleanPrefix ||
			strings.HasPrefix(cleanPath, cleanPrefix+string(os.PathSeparator)) {
			return true
		}
	}

	return false
}

func (h *Handler) parseOutgoingRequest(w http.ResponseWriter, r *http.Request) (sharesoutgoing.OutgoingShareRequest, *identity.User, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return sharesoutgoing.OutgoingShareRequest{}, nil, false
	}

	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")

		return sharesoutgoing.OutgoingShareRequest{}, nil, false
	}

	var req sharesoutgoing.OutgoingShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteBadRequest(w, api.ReasonBadRequest, "failed to parse request")

		return sharesoutgoing.OutgoingShareRequest{}, nil, false
	}

	if req.ReceiverDomain == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "receiverDomain is required")

		return sharesoutgoing.OutgoingShareRequest{}, nil, false
	}

	if req.ShareWith == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "shareWith is required")

		return sharesoutgoing.OutgoingShareRequest{}, nil, false
	}

	if req.LocalPath == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "localPath is required")

		return sharesoutgoing.OutgoingShareRequest{}, nil, false
	}

	if len(req.Permissions) == 0 {
		api.WriteBadRequest(w, api.ReasonMissingField, "permissions is required")

		return sharesoutgoing.OutgoingShareRequest{}, nil, false
	}

	for _, perm := range req.Permissions {
		supported := slices.Contains(spec.SupportedWebDAVPermissions, perm)

		if !supported {
			api.WriteBadRequest(w, api.ReasonInvalidField, "permissions must be read-only")

			return sharesoutgoing.OutgoingShareRequest{}, nil, false
		}
	}

	return req, user, true
}

func (h *Handler) resolveLocalResource(w http.ResponseWriter, _ *http.Request, req sharesoutgoing.OutgoingShareRequest) (string, string, string, bool) {
	cleanPath, err := h.validateLocalPath(req.LocalPath)
	if err != nil {
		api.WriteBadRequest(w, api.ReasonInvalidField, err.Error())

		return "", "", "", false
	}

	stat, err := os.Stat(cleanPath)
	if err != nil {
		api.WriteBadRequest(w, api.ReasonInvalidField, "file does not exist")

		return "", "", "", false
	}

	resourceType := req.ResourceType
	if resourceType == "" {
		if stat.IsDir() {
			resourceType = "folder"
		} else {
			resourceType = "file"
		}
	}

	name := req.Name
	if name == "" {
		name = filepath.Base(cleanPath)
	}

	return cleanPath, resourceType, name, true
}

func (h *Handler) generateShareIdentifiers(w http.ResponseWriter, _ *http.Request) (uuid.UUID, uuid.UUID, string, bool) {
	providerID, err := uuid.NewV7()
	if err != nil {
		h.logger.Error("failed to generate provider id", "error", err)
		api.WriteInternalError(w, "failed to create share")

		return uuid.UUID{}, uuid.UUID{}, "", false
	}

	webdavID, err := uuid.NewV7()
	if err != nil {
		h.logger.Error("failed to generate webdav id", "error", err)
		api.WriteInternalError(w, "failed to create share")

		return uuid.UUID{}, uuid.UUID{}, "", false
	}

	sharedSecret, err := generateSharedSecret()
	if err != nil {
		h.logger.Error("failed to generate shared secret", "error", err)
		api.WriteInternalError(w, "failed to create share")

		return uuid.UUID{}, uuid.UUID{}, "", false
	}

	return providerID, webdavID, sharedSecret, true
}

func (h *Handler) resolveReceiverAndRequirements(w http.ResponseWriter, r *http.Request, req sharesoutgoing.OutgoingShareRequest) (resolvedPeerOrigin, *spec.Discovery, []string, bool) {
	origin := h.resolvePeerOrigin(req.ReceiverDomain)
	if origin.baseURL == "" || origin.peerDomain == "" {
		h.logger.Warn("receiver origin resolution failed", "receiver", req.ReceiverDomain)
		api.WriteError(w, reason.APIStatus(reason.PeerDiscoveryFailed), reason.PeerDiscoveryFailed,
			"could not resolve receiver origin")

		return resolvedPeerOrigin{}, nil, nil, false
	}

	disc, err := h.discoveryClient.Discover(r.Context(), origin.baseURL)
	if err != nil {
		h.logger.Warn("receiver discovery failed", "receiver", req.ReceiverDomain, "error", err)
		api.WriteError(w, reason.APIStatus(reason.PeerDiscoveryFailed), reason.PeerDiscoveryFailed,
			"could not discover receiver")

		return resolvedPeerOrigin{}, nil, nil, false
	}

	facts := policy.Facts{}
	if h.resolver != nil {
		facts = h.resolver.ResolveFacts(origin.peerDomain)
	}

	mustInclude := mustIncludeTokenExchange(facts, disc)
	requirements := tokenExchangeRequirements(mustInclude)

	if mustInclude && h.localTokenEndPoint == "" {
		h.logger.Warn("local sender is not configured for token exchange",
			"has_token_endpoint", h.localTokenEndPoint != "")
		api.WriteError(w, reason.APIStatus(reason.PeerCapabilityMismatch), reason.PeerCapabilityMismatch,
			"local sender is not configured for token exchange")

		return resolvedPeerOrigin{}, nil, nil, false
	}

	if mustInclude && !disc.SupportsTokenExchange() {
		h.logger.Warn("receiver lacks token-exchange capability", "receiver", req.ReceiverDomain)
		api.WriteError(w, reason.APIStatus(reason.PeerCapabilityMismatch), reason.PeerCapabilityMismatch,
			"receiver does not advertise exchange-token with tokenEndPoint")

		return resolvedPeerOrigin{}, nil, nil, false
	}

	return origin, disc, requirements, true
}

func (h *Handler) buildWebDAVURI(w http.ResponseWriter, _ *http.Request, req sharesoutgoing.OutgoingShareRequest, webdavID uuid.UUID, disc *spec.Discovery) (string, bool) {
	webdavURI := webdavID.String()
	if disc.WebDAVReceiveURIKind() == spec.WebDAVReceiveURIAbsolute {
		absURI, buildErr := disc.BuildWebDAVURL(webdavID.String())
		if buildErr != nil {
			h.logger.Warn("failed to build absolute webdav uri", "receiver", req.ReceiverDomain, "error", buildErr)
			api.WriteError(w, reason.APIStatus(reason.PeerCapabilityMismatch), reason.PeerCapabilityMismatch,
				"receiver webdav-receive absolute uri could not be built")

			return "", false
		}

		if h.peerOrigin == nil || !h.peerOrigin.IsAbsoluteURIAllowed(absURI, req.ReceiverDomain) {
			h.logger.Warn("absolute webdav uri failed peer authority check",
				"receiver", req.ReceiverDomain, "uri", absURI)
			api.WriteError(w, reason.APIStatus(reason.PeerCapabilityMismatch), reason.PeerCapabilityMismatch,
				"receiver webdav-receive absolute uri failed authority check")

			return "", false
		}

		webdavURI = absURI
	}

	return webdavURI, true
}
