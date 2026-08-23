// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// reverseInviteRequest is the paste body, shape-compatible with the inbox
// invite import request.
type reverseInviteRequest struct {
	InviteString string `json:"inviteString"`
}

// reverseInviteResponse is the safe paste result: no token, invite string, or
// recipient identity leaks.
type reverseInviteResponse struct {
	Status string `json:"status"`
}

// HandleReverseInvite serves POST /validator/api/session/{id}/reverse-invite.
// It validates the pasted invite against the active run's target host,
// pastes first-token-wins into reverse_invite_accepted, and continues into
// product acceptance in the same request. Reverse solicitation is owned by
// the active runner; paste is accepted only in reverse_awaiting_invite.
func (s *Service) HandleReverseInvite(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "id")
	if runID == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "id is required")

		return
	}

	var req reverseInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteBadRequest(w, api.ReasonMissingField, "invalid request body")

		return
	}

	if req.InviteString == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "inviteString is required")

		return
	}

	run, ok := s.resolvePasteSession(w, r.Context(), runID)
	if !ok {
		return
	}

	token, sender, parseErr := s.parsePasteInvite(req.InviteString, run.TargetHost)
	if parseErr != nil {
		if errors.Is(parseErr, ErrWrongTargetHost) {
			api.WriteError(w, http.StatusUnprocessableEntity, "wrong_target_host", "invite sender does not match the session target host")

			return
		}

		api.WriteBadRequest(w, api.ReasonMissingField, parseErr.Error())

		return
	}

	if !pasteImportReady(run.State) {
		api.WriteConflict(w, "session state does not allow this step")

		return
	}

	ctx := r.Context()

	invite, err := s.createOrReuseIncoming(ctx, req.InviteString, token, sender, *run.BobUserID)
	if err != nil {
		s.log.Error("reverseinvite: create or reuse incoming invite", "error", err)
		api.WriteInternalError(w, "failed to store invite")

		return
	}

	if err := s.deps.Store.ImportReverseInvite(ctx, runID, token, invite.ID); err != nil {
		s.writeStepError(w, "import reverse invite", err)

		return
	}

	if err := s.AcceptIncoming(ctx, runID); err != nil {
		s.writeStepError(w, "accept reverse invite", err)

		return
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(reverseInviteResponse{Status: string(invites.InviteStatusAccepted)}); err != nil {
		s.log.Error("reverseinvite: encode paste response", "error", err)
	}
}

// resolvePasteSession loads the named run and proves it is the active run
// with Bob already bound, writing the HTTP error on failure.
func (s *Service) resolvePasteSession(w http.ResponseWriter, ctx context.Context, runID string) (*validatorcore.TestRun, bool) {
	run, err := s.deps.Store.GetTestRun(ctx, runID)
	if err != nil {
		if errors.Is(err, validatorcore.ErrSessionNotFound) {
			api.WriteNotFound(w, "session not found")

			return nil, false
		}

		s.log.Error("reverseinvite: load session", "error", err)
		api.WriteInternalError(w, "failed to load session")

		return nil, false
	}

	if !run.IsActive {
		api.WriteConflict(w, "session is not active")

		return nil, false
	}

	if run.BobUserID == nil || *run.BobUserID == "" {
		api.WriteConflict(w, "session has no bound recipient")

		return nil, false
	}

	return run, true
}

// parsePasteInvite decodes the pasted invite string and proves the sender
// normalizes to the run's target host. A host mismatch is reported as
// ErrWrongTargetHost; malformed input as a plain descriptive error.
func (s *Service) parsePasteInvite(inviteString, targetHost string) (token, sender string, err error) {
	token, sender, err = invites.ParseInviteString(inviteString)
	if err != nil {
		return "", "", errors.New("invalid invite string")
	}

	senderNormalized, err := hostport.Normalize(sender, s.deps.LocalIdentity.Scheme)
	if err != nil {
		return "", "", errors.New("invalid invite sender host")
	}

	if senderNormalized != targetHost {
		// Wrong host is rejected before any CAS or write.
		return "", "", ErrWrongTargetHost
	}

	return token, sender, nil
}

// pasteImportReady reports whether poll may honestly show paste_s2. Paste
// imports and accepts only in reverse_awaiting_invite; earlier and later
// states are rejected without writes.
func pasteImportReady(state string) bool {
	return state == validatorcore.StateReverseAwaitingInvite
}

// writeStepError maps orchestration failures onto honest HTTP statuses.
func (s *Service) writeStepError(w http.ResponseWriter, step string, err error) {
	switch {
	case errors.Is(err, validatorcore.ErrShareCorrelationConflict):
		api.WriteConflict(w, "a different reverse invite is already imported")
	case errors.Is(err, validatorcore.ErrStateTransitionMiss):
		api.WriteConflict(w, "session state does not allow this step")
	case errors.Is(err, ErrSessionNotActive), errors.Is(err, ErrBobNotBound), errors.Is(err, ErrBobPartyMissing):
		api.WriteConflict(w, "session is not ready for a reverse invite")
	case errors.Is(err, ErrCorrelationMismatch):
		api.WriteConflict(w, "invite does not match the session correlation")
	default:
		s.log.Error("reverseinvite: "+step, "error", err)
		api.WriteError(w, http.StatusBadGateway, api.ReasonPeerUnreachable, "failed to complete the reverse invite exchange")
	}
}

// createOrReuseIncoming stores the pasted invite for Bob, or returns the
// existing Bob-owned row for the same token.
func (s *Service) createOrReuseIncoming(
	ctx context.Context,
	inviteString, token, sender, bobID string,
) (*invitesincoming.IncomingInvite, error) {
	invite, err := s.deps.IncomingInvites.GetByTokenForRecipientUserID(ctx, token, bobID)
	if err == nil {
		return invite, nil
	}

	if !errors.Is(err, invites.ErrInviteNotFound) {
		return nil, fmt.Errorf("reverseinvite: look up incoming invite: %w", err)
	}

	invite = &invitesincoming.IncomingInvite{
		InviteString:    inviteString,
		Token:           token,
		SenderFQDN:      sender,
		RecipientUserID: bobID,
		ReceivedAt:      time.Now(),
		Status:          invites.InviteStatusPending,
	}
	if err := s.deps.IncomingInvites.Create(ctx, invite); err != nil {
		if !errors.Is(err, store.ErrAlreadyExists) {
			return nil, fmt.Errorf("reverseinvite: store incoming invite: %w", err)
		}

		// A concurrent paste stored the same token first; reuse that row.
		existing, getErr := s.deps.IncomingInvites.GetByTokenForRecipientUserID(ctx, token, bobID)
		if getErr != nil {
			return nil, fmt.Errorf("reverseinvite: load duplicate incoming invite: %w", getErr)
		}

		return existing, nil
	}

	return invite, nil
}
