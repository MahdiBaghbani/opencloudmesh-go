// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	ocmshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// dispatchReleaseTimeout bounds the detached context used to release a send
// permit after the client request is already gone.
const dispatchReleaseTimeout = 30 * time.Second

// Sentinel errors a DispatchHook returns from GuardCreate. The handler maps
// them to refusal responses; any other error is an internal failure.
var (
	// ErrDispatchRefused rejects an outgoing share before any local
	// persistence or outbound call.
	ErrDispatchRefused = errors.New("outgoing share dispatch refused")

	// ErrDispatchInProgress rejects a dispatch whose send permit is already
	// owned by another in-flight dispatcher.
	ErrDispatchInProgress = errors.New("outgoing share dispatch already in progress")
)

// DispatchPlan carries the reserved dispatch identity for one guarded
// outgoing share. A non-nil ReplayShare short-circuits the create flow: the
// share was already delivered, so the handler answers from the stored
// snapshot without a second outbound POST. A non-empty WebDAVURI pins the
// exact wire URI from the first attempt, so a retried send never rebuilds a
// drifted URI from fresh discovery.
type DispatchPlan struct {
	TestRunID    string
	ProviderID   string
	WebDAVID     string
	WebDAVURI    string
	SharedSecret string
	// ClaimToken fences the send permit to this attempt: a stale claim
	// reclaimed by a later dispatcher carries a new token, and every
	// owner-side write (snapshot, remote-sent stamp, release) must present
	// the current token or fail closed.
	ClaimToken  string
	ReplayShare *sharesoutgoing.OutgoingShare
}

// DispatchHook is the optional policy seat on the outgoing share flow. A nil
// hook keeps the generic behavior: every authenticated share is created and
// delivered without dispatch policy.
type DispatchHook interface {
	// GuardCreate runs after request parsing, before any local persistence
	// or outbound call. It returns the reserved dispatch plan for the one
	// allowed dispatch, a replay plan for an already-delivered dispatch, or
	// a refusal error.
	GuardCreate(ctx context.Context, req sharesoutgoing.OutgoingShareRequest, userID string) (*DispatchPlan, error)

	// NoteWireURI records the exact WebDAV URI a planned dispatch is about
	// to put on the wire. It runs after the URI is built and before local
	// persistence, so a later retry can replay the identical payload.
	NoteWireURI(ctx context.Context, plan *DispatchPlan, webdavURI string) error

	// CheckSendClaim runs after the planned share and payload are prepared,
	// immediately before the outbound POST. It fails when the plan's send
	// permit was reclaimed by a later dispatcher, so a fenced stale plan
	// never reaches the receiver. A nil plan is a no-op.
	CheckSendClaim(ctx context.Context, plan *DispatchPlan) error

	// CommitSent runs after the outbound POST succeeded and before the
	// success response. A nil plan is a no-op.
	CommitSent(ctx context.Context, plan *DispatchPlan, share *sharesoutgoing.OutgoingShare) error

	// AbortSend runs when a planned dispatch will not complete its send in
	// this request, releasing the send permit so a later attempt can retry
	// with the same reserved identity. A nil plan is a no-op.
	AbortSend(ctx context.Context, plan *DispatchPlan) error
}

// SetDispatchHook installs the optional dispatch hook. A nil hook keeps the
// generic flow.
func (h *Handler) SetDispatchHook(hook DispatchHook) {
	h.dispatchHook = hook
}

// DeliverWithPlan drives the delivery path with a dispatch plan the hook
// already granted. It exists so dispatch-flow tests can complete a send from
// a plan obtained earlier (for example after a permit reclaim) without
// re-entering the guard, which would refuse the already-claimed permit.
func (h *Handler) DeliverWithPlan(
	w http.ResponseWriter,
	r *http.Request,
	req sharesoutgoing.OutgoingShareRequest,
	user *identity.User,
	plan *DispatchPlan,
) {
	cleanPath, resourceType, name, ok := h.resolveLocalResource(w, r, req)
	if !ok {
		return
	}

	h.deliverOutgoingShare(w, r, req, user, cleanPath, resourceType, name, plan)
}

// guardDispatch runs the optional hook after request parsing, before any
// local persistence or outbound call. It writes the refusal or replay
// response itself and reports whether the generic flow may proceed.
func (h *Handler) guardDispatch(
	w http.ResponseWriter,
	r *http.Request,
	req sharesoutgoing.OutgoingShareRequest,
	userID string,
) (*DispatchPlan, bool) {
	if h.dispatchHook == nil {
		return nil, true
	}

	plan, err := h.dispatchHook.GuardCreate(r.Context(), req, userID)
	if err != nil {
		h.writeDispatchGuardError(w, err)

		return nil, false
	}

	if plan != nil && plan.ReplayShare != nil {
		h.writeShareCreated(w, plan.ReplayShare)

		return nil, false
	}

	return plan, true
}

func (h *Handler) writeDispatchGuardError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrDispatchRefused):
		api.WriteError(w, http.StatusForbidden, "dispatch_refused", "outgoing share refused by the active validation session")
	case errors.Is(err, ErrDispatchInProgress):
		api.WriteConflict(w, "share dispatch already in progress")
	default:
		h.logger.Error("dispatch guard failed", "error", err)
		api.WriteInternalError(w, "failed to guard outgoing share")
	}
}

// plannedShareIdentifiers returns the reserved identifiers for a planned
// dispatch, or mints fresh ones for the generic flow.
func (h *Handler) plannedShareIdentifiers(w http.ResponseWriter, r *http.Request, plan *DispatchPlan) (uuid.UUID, uuid.UUID, string, bool) {
	if plan == nil {
		return h.generateShareIdentifiers(w, r)
	}

	providerID, err := uuid.Parse(plan.ProviderID)
	if err != nil {
		h.logger.Error("invalid planned provider id", "error", err)
		api.WriteInternalError(w, "failed to create share")

		return uuid.UUID{}, uuid.UUID{}, "", false
	}

	webdavID, err := uuid.Parse(plan.WebDAVID)
	if err != nil {
		h.logger.Error("invalid planned webdav id", "error", err)
		api.WriteInternalError(w, "failed to create share")

		return uuid.UUID{}, uuid.UUID{}, "", false
	}

	return providerID, webdavID, plan.SharedSecret, true
}

// persistPlannedShare stores the share, or loads the row a crashed earlier
// attempt already persisted under the reserved provider ID, so a retry never
// mints a second local share for the same dispatch.
func (h *Handler) persistPlannedShare(
	w http.ResponseWriter,
	r *http.Request,
	share *sharesoutgoing.OutgoingShare,
) (*sharesoutgoing.OutgoingShare, bool) {
	if err := h.repo.Create(r.Context(), share); err == nil {
		return share, true
	}

	existing, err := h.repo.GetByProviderID(r.Context(), share.ProviderID)
	if err != nil {
		h.logger.Error("failed to store outgoing share", "provider_id", share.ProviderID, "error", err)
		api.WriteInternalError(w, "failed to create share")

		return nil, false
	}

	return existing, true
}

// dispatchWebDAVURI resolves the wire URI for the share. A planned dispatch
// with a pinned URI reuses the exact first-attempt value; a first planned
// attempt builds from discovery and reports the result to the hook so the
// reservation snapshots it before anything is persisted or sent.
func (h *Handler) dispatchWebDAVURI(
	w http.ResponseWriter,
	r *http.Request,
	req sharesoutgoing.OutgoingShareRequest,
	plan *DispatchPlan,
	webdavID uuid.UUID,
	disc *spec.Discovery,
) (string, bool) {
	if plan == nil {
		return h.buildWebDAVURI(w, r, req, webdavID, disc)
	}

	if plan.WebDAVURI != "" {
		return plan.WebDAVURI, true
	}

	webdavURI, ok := h.buildWebDAVURI(w, r, req, webdavID, disc)
	if !ok {
		return "", false
	}

	if err := h.dispatchHook.NoteWireURI(r.Context(), plan, webdavURI); err != nil {
		h.logger.Error("failed to snapshot dispatch wire uri", "error", err)
		api.WriteInternalError(w, "failed to create share")

		return "", false
	}

	// Pin the exact URI on the plan so the post-send commit proves the CAS
	// against the value this attempt actually put on the wire.
	plan.WebDAVURI = webdavURI

	return webdavURI, true
}

// checkSendClaim verifies a planned dispatch still owns the send permit
// immediately before the outbound POST. A fenced stale plan is refused here,
// before the receiver can see a duplicate POST.
func (h *Handler) checkSendClaim(w http.ResponseWriter, r *http.Request, plan *DispatchPlan) bool {
	if err := h.dispatchHook.CheckSendClaim(r.Context(), plan); err != nil {
		h.logger.Warn("dispatch send permit lost before send", "test_run_id", plan.TestRunID, "error", err)
		api.WriteConflict(w, "share dispatch permit superseded by a retry")

		return false
	}

	return true
}

// buildWebDAVURI resolves the receiver's webdav-receive URI kind into the
// exact wire URI for the share.
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

// outgoingSharePayload builds the wire payload from the stored share row, so
// a retried dispatch replays the exact snapshot the first attempt persisted.
func outgoingSharePayload(share *sharesoutgoing.OutgoingShare, webdavURI string) spec.NewShareRequest {
	return spec.NewShareRequest{
		ShareWith:    share.ShareWith,
		Name:         share.Name,
		ProviderID:   share.ProviderID,
		Owner:        share.Owner,
		Sender:       share.Sender,
		ShareType:    share.ShareType,
		ResourceType: share.ResourceType,
		Protocol: spec.Protocol{
			Name: "multi",
			WebDAV: &spec.WebDAVProtocol{
				URI:          webdavURI,
				SharedSecret: share.SharedSecret,
				Permissions:  share.Permissions,
				Requirements: share.Requirements,
			},
		},
	}
}

// deliverShare posts the payload to the receiver. A planned dispatch must
// still own the send permit at the wire: a plan whose claim was reclaimed by
// a later dispatcher is refused before the receiver can see a duplicate POST.
// On failure it marks the local row failed and writes the delivery error
// response.
func (h *Handler) deliverShare(
	w http.ResponseWriter,
	r *http.Request,
	req sharesoutgoing.OutgoingShareRequest,
	origin resolvedPeerOrigin,
	disc *spec.Discovery,
	share *sharesoutgoing.OutgoingShare,
	payload spec.NewShareRequest,
	plan *DispatchPlan,
) bool {
	if plan != nil && !h.checkSendClaim(w, r, plan) {
		return false
	}

	if err := h.sendShareToReceiver(r.Context(), origin, disc, payload); err != nil {
		h.logger.Warn("failed to deliver share to receiver", "receiver", req.ReceiverDomain, "error", err)

		share.Status = ocmshares.OutgoingShareStatusFailed
		share.Error = err.Error()

		if uerr := h.repo.Update(r.Context(), share); uerr != nil {
			h.logger.Error("failed to mark outgoing share as failed", "share_id", share.ShareID, "error", uerr)
		}

		api.WriteError(w, http.StatusBadGateway, reason.PeerUnreachable, "failed to deliver share to receiver")

		return false
	}

	return true
}

// writeShareCreated writes the 201 response shared by the delivered and the
// replayed dispatch paths.
func (h *Handler) writeShareCreated(w http.ResponseWriter, share *sharesoutgoing.OutgoingShare) {
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
