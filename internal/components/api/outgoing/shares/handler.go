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
	"fmt"
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
	dispatchHook       DispatchHook
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

	// Local resource validation runs before the dispatch guard so an
	// invalid path can never create or strand a dispatch reservation.
	cleanPath, resourceType, name, ok := h.resolveLocalResource(w, r, req)
	if !ok {
		return
	}

	plan, ok := h.guardDispatch(w, r, req, user.ID)
	if !ok {
		return
	}

	h.deliverOutgoingShare(w, r, req, user, cleanPath, resourceType, name, plan)
}

// deliverOutgoingShare persists the share and delivers it to the receiver. A
// granted plan owns the single send permit; any exit before a recorded
// delivery must release it so a later attempt can retry.
func (h *Handler) deliverOutgoingShare(
	w http.ResponseWriter,
	r *http.Request,
	req sharesoutgoing.OutgoingShareRequest,
	user *identity.User,
	cleanPath string,
	resourceType string,
	name string,
	plan *DispatchPlan,
) {
	delivered := false

	if plan != nil {
		defer func(ctx context.Context) {
			if delivered {
				return
			}

			// The release must outlive the client request: a canceled
			// request context would fail the write and strand the claimed
			// permit.
			releaseCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), dispatchReleaseTimeout)
			defer stop()

			if err := h.dispatchHook.AbortSend(releaseCtx, plan); err != nil {
				h.logger.Error("failed to release dispatch permit", "test_run_id", plan.TestRunID, "error", err)
			}
		}(r.Context())
	}

	providerID, webdavID, sharedSecret, ok := h.plannedShareIdentifiers(w, r, plan)
	if !ok {
		return
	}

	origin, disc, requirements, ok := h.resolveReceiverAndRequirements(w, r, req)
	if !ok {
		return
	}

	webdavURI, ok := h.dispatchWebDAVURI(w, r, req, plan, webdavID, disc)
	if !ok {
		return
	}

	owner := address.FormatOutgoingOCMAddressFromUserID(user.ID, h.localProvider)
	sender := address.FormatOutgoingOCMAddressFromUserID(user.ID, h.localProvider)

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
		Status:           ocmshares.OutgoingShareStatusPending,
		Requirements:     requirements,
	}

	if plan != nil {
		stored, ok := h.persistPlannedShare(w, r, share)
		if !ok {
			return
		}

		share = stored
	} else if err := h.repo.Create(r.Context(), share); err != nil {
		h.logger.Error("failed to store outgoing share", "error", err)
		api.WriteInternalError(w, "failed to create share")

		return
	}

	// The payload is built from the persisted row, so a retried dispatch
	// replays the exact snapshot the first attempt stored.
	payload := outgoingSharePayload(share, webdavURI)

	if !h.deliverShare(w, r, req, origin, disc, share, payload, plan) {
		return
	}

	// The delivery is recorded from here on: a later failure must not release
	// the send permit, because the receiver may already hold the share.
	delivered = true

	// The dispatch commit runs before the local sent stamp so a stamp failure
	// still leaves a remote_sent reservation the next replay can reconcile.
	// Like the permit release, the commit must outlive the client request: a
	// client that disconnects after the receiver accepted the share must not
	// abort the CAS and strand the reservation at remote_sent.
	if plan != nil {
		commitCtx, stop := context.WithTimeout(context.WithoutCancel(r.Context()), dispatchReleaseTimeout)
		defer stop()

		if err := h.dispatchHook.CommitSent(commitCtx, plan, share); err != nil {
			h.logger.Error("failed to commit dispatched share", "share_id", share.ShareID, "error", err)
			api.WriteInternalError(w, "share sent but session commit failed")

			return
		}
	}

	share.Status = ocmshares.OutgoingShareStatusSent
	share.Error = ""
	sentAt := time.Now()
	share.SentAt = &sentAt

	if err := h.repo.Update(r.Context(), share); err != nil {
		h.logger.Error("failed to mark outgoing share as sent", "share_id", share.ShareID, "error", err)
		api.WriteInternalError(w, "share sent but local persistence failed")

		return
	}

	h.logger.Info("outgoing share created and sent",
		"share_id", share.ShareID,
		"provider_id", share.ProviderID,
		"receiver", req.ReceiverDomain)

	h.writeShareCreated(w, share)
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

	if stat.IsDir() {
		api.WriteBadRequest(w, api.ReasonInvalidField, "directory shares are not supported; only single files")

		return "", "", "", false
	}

	resourceType := req.ResourceType
	if resourceType == "" {
		resourceType = "file"
	} else if resourceType != spec.SupportedResourceTypes[0] {
		api.WriteBadRequest(w, api.ReasonInvalidField, fmt.Sprintf(
			"resource type %q is not supported; only %q is supported",
			resourceType,
			spec.SupportedResourceTypes[0],
		))

		return "", "", "", false
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
