// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package forwardshare

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// dispatchClaimStaleSeconds bounds how long a claimed send permit may go
// without progress before a retry may reclaim it. It only guards against a
// dead owner; a live send holds a fresh permit and keeps it.
const dispatchClaimStaleSeconds int64 = 30

// GuardCreate implements the outgoing-share dispatch hook. With no active run
// the guard is a no-op and the generic flow proceeds. With an active run every
// share is refused except the one designated dispatch: the session's own
// dispatching party (whose local user ID is the run ID) sharing the
// snapshotted probe path with the designated recipient at the run's target
// host. The designated dispatch reserves its outbox row and takes the single
// send permit before the handler persists or sends anything.
func (s *Service) GuardCreate(
	ctx context.Context,
	req sharesoutgoing.OutgoingShareRequest,
	userID string,
) (*outgoingshares.DispatchPlan, error) {
	runID, err := s.deps.Store.FindOneActive(ctx, validatorcore.LocalIdentityA)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil //nolint:nilnil // intentional: (nil, nil) means no active run; the generic path proceeds
	}

	if err != nil {
		return nil, fmt.Errorf("forwardshare: find active run: %w", err)
	}

	run, err := s.deps.Store.GetTestRun(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("forwardshare: load active run: %w", err)
	}

	// Only the session's own dispatching party may dispatch while its run is
	// active; every other local user, bound recipient or not, is refused even
	// when the request matches the designated dispatch exactly.
	if userID != run.TestRunID {
		return nil, outgoingshares.ErrDispatchRefused
	}

	reservation, err := s.deps.Store.GetDispatchReservation(ctx, runID)
	switch {
	case err == nil:
		return s.guardExisting(ctx, run, reservation, req)
	case errors.Is(err, validatorcore.ErrDispatchReservationNotFound):
		return s.guardFirstDispatch(ctx, run, req)
	default:
		return nil, fmt.Errorf("forwardshare: load dispatch reservation: %w", err)
	}
}

// guardFirstDispatch handles the first designated dispatch for a run: prove
// the request is the designated share, reserve the outbox row with freshly
// minted identifiers, and take the send permit.
func (s *Service) guardFirstDispatch(
	ctx context.Context,
	run *validatorcore.TestRun,
	req sharesoutgoing.OutgoingShareRequest,
) (*outgoingshares.DispatchPlan, error) {
	designated, ok := s.designatedShareWith(run)
	if !ok || run.State != validatorcore.StateReverseInviteAccepted {
		return nil, outgoingshares.ErrDispatchRefused
	}

	if !s.requestMatchesDesignated(req, run, designated) {
		return nil, outgoingshares.ErrDispatchRefused
	}

	providerID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("forwardshare: mint provider id: %w", err)
	}

	webdavID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("forwardshare: mint webdav id: %w", err)
	}

	sharedSecret, err := generateSharedSecret()
	if err != nil {
		return nil, fmt.Errorf("forwardshare: mint shared secret: %w", err)
	}

	in := validatorcore.ForwardDispatchReservation{
		TestRunID:           run.TestRunID,
		ProviderID:          providerID.String(),
		WebDAVID:            webdavID.String(),
		SharedSecret:        sharedSecret,
		ReceiverHost:        run.TargetHost,
		ShareWith:           designated,
		DesignatedShareWith: *run.DesignatedShareWith,
		ProbeFilePath:       filepath.Clean(req.LocalPath),
	}

	if reserveErr := s.deps.Store.ReserveForwardDispatch(ctx, in); reserveErr != nil {
		switch {
		case errors.Is(reserveErr, validatorcore.ErrDispatchReservationExists):
			// A concurrent dispatcher reserved first; re-enter through the
			// existing-reservation path so the winner's identity decides.
			return s.guardReloaded(ctx, run, req)
		case errors.Is(reserveErr, validatorcore.ErrStateTransitionMiss):
			return nil, outgoingshares.ErrDispatchRefused
		default:
			return nil, fmt.Errorf("forwardshare: reserve dispatch: %w", reserveErr)
		}
	}

	claimToken, err := mintClaimToken()
	if err != nil {
		return nil, err
	}

	if err := s.deps.Store.ClaimForwardDispatchSend(ctx, run.TestRunID, in.ProviderID, claimToken); err != nil {
		return s.handleClaimMiss(ctx, run, req)
	}

	return &outgoingshares.DispatchPlan{
		TestRunID:    run.TestRunID,
		ProviderID:   in.ProviderID,
		WebDAVID:     in.WebDAVID,
		SharedSecret: in.SharedSecret,
		ClaimToken:   claimToken,
	}, nil
}

// guardExisting handles a dispatch request when the outbox row already
// exists: the request must match the reservation snapshot, then the
// reservation status decides between replay, a retried claim, or an
// in-progress refusal.
func (s *Service) guardExisting(
	ctx context.Context,
	run *validatorcore.TestRun,
	reservation *validatorcore.DispatchReservation,
	req sharesoutgoing.OutgoingShareRequest,
) (*outgoingshares.DispatchPlan, error) {
	if !s.requestMatchesReservation(req, reservation) {
		return nil, outgoingshares.ErrDispatchRefused
	}

	switch reservation.Status {
	case validatorcore.DispatchStatusRemoteSent, validatorcore.DispatchStatusCASCommitted:
		return s.replay(ctx, run, reservation)
	case validatorcore.DispatchStatusReserved:
		// Reserved but not sent: an earlier attempt crashed before the send
		// or released the permit after a failed send. Adopt the reservation,
		// retake the permit under a fresh claim token, and pin the exact wire
		// identity the first attempt established.
		claimToken, err := mintClaimToken()
		if err != nil {
			return nil, err
		}

		if err := s.deps.Store.ClaimForwardDispatchSend(ctx, run.TestRunID, reservation.ProviderID, claimToken); err != nil {
			return s.handleClaimMiss(ctx, run, req)
		}

		return s.retryPlan(ctx, run, reservation, claimToken)
	default:
		// Claimed but not yet sent: another dispatcher owns the permit. A
		// permit whose owner stopped making progress (crash, or a canceled
		// request whose release never ran) is reclaimed once stale so the
		// run is never stranded; a fresh permit stays in progress. The
		// reclaim is a compare-and-swap on the observed claim token, so a
		// permit that changed hands since the load is left alone, and the
		// rotation fences the old owner out of every owner-side write.
		claimToken, err := mintClaimToken()
		if err != nil {
			return nil, err
		}

		observed := ""
		if reservation.OutgoingShareID != nil {
			observed = *reservation.OutgoingShareID
		}

		staleBefore := time.Now().Unix() - dispatchClaimStaleSeconds
		if err := s.deps.Store.ReclaimForwardDispatchClaim(ctx, run.TestRunID, reservation.ProviderID, observed, claimToken, staleBefore); err != nil {
			return nil, outgoingshares.ErrDispatchInProgress
		}

		return s.retryPlan(ctx, run, reservation, claimToken)
	}
}

// retryPlan builds the dispatch plan for a retried send. When the first
// attempt persisted its local share row, the reservation's webdav identity
// holds the exact wire URI that attempt put on the wire, and the retry pins
// it so discovery drift can never change the payload. When no local row
// exists the first attempt crashed before building anything, so the retry
// builds fresh and snapshots again.
func (s *Service) retryPlan(
	ctx context.Context,
	run *validatorcore.TestRun,
	reservation *validatorcore.DispatchReservation,
	claimToken string,
) (*outgoingshares.DispatchPlan, error) {
	plan := &outgoingshares.DispatchPlan{
		TestRunID:    run.TestRunID,
		ProviderID:   reservation.ProviderID,
		SharedSecret: reservation.SharedSecret,
		ClaimToken:   claimToken,
	}

	share, err := s.deps.OutgoingShares.GetByProviderID(ctx, reservation.ProviderID)
	switch {
	case err == nil:
		plan.WebDAVID = share.WebDAVID
		plan.WebDAVURI = reservation.WebDAVID
	case errors.Is(err, sharesoutgoing.ErrShareNotFound):
		// The bare ID is the last path segment of the wire URI in both the
		// relative and the absolute form.
		plan.WebDAVID = path.Base(reservation.WebDAVID)
	default:
		return nil, fmt.Errorf("forwardshare: load dispatched share for retry: %w", err)
	}

	return plan, nil
}

// guardReloaded re-enters the guard after losing the reserve race.
func (s *Service) guardReloaded(
	ctx context.Context,
	run *validatorcore.TestRun,
	req sharesoutgoing.OutgoingShareRequest,
) (*outgoingshares.DispatchPlan, error) {
	reservation, err := s.deps.Store.GetDispatchReservation(ctx, run.TestRunID)
	if err != nil {
		return nil, fmt.Errorf("forwardshare: reload reservation after reserve race: %w", err)
	}

	return s.guardExisting(ctx, run, reservation, req)
}

// handleClaimMiss classifies a lost permit race: if the winner already
// delivered, reconcile as a replay; otherwise the send is in progress.
func (s *Service) handleClaimMiss(
	ctx context.Context,
	run *validatorcore.TestRun,
	req sharesoutgoing.OutgoingShareRequest,
) (*outgoingshares.DispatchPlan, error) {
	reservation, err := s.deps.Store.GetDispatchReservation(ctx, run.TestRunID)
	if err != nil {
		return nil, fmt.Errorf("forwardshare: reload reservation after claim miss: %w", err)
	}

	if reservation.Status == validatorcore.DispatchStatusRemoteSent ||
		reservation.Status == validatorcore.DispatchStatusCASCommitted {
		if !s.requestMatchesReservation(req, reservation) {
			return nil, outgoingshares.ErrDispatchRefused
		}

		return s.replay(ctx, run, reservation)
	}

	return nil, outgoingshares.ErrDispatchInProgress
}

// designatedShareWith parses the run's pinned designated recipient into the
// plain user@provider compare form. A bare accepted user ID is paired with
// the run's target host; a full address must normalize to the target host.
// Anything else fails closed.
func (s *Service) designatedShareWith(run *validatorcore.TestRun) (string, bool) {
	if run.DesignatedShareWith == nil || *run.DesignatedShareWith == "" {
		return "", false
	}

	raw := *run.DesignatedShareWith

	user, provider, err := address.Parse(raw)
	if err != nil {
		// Bare accepted user ID: the invite acceptance already proved the
		// provider is the run's target host.
		user, provider = raw, run.TargetHost
	}

	normalized, err := hostport.Normalize(provider, s.deps.LocalIdentity.Scheme)
	if err != nil || normalized != run.TargetHost {
		return "", false
	}

	return user + "@" + normalized, true
}

// requestMatchesDesignated reports whether the request is the run's
// designated dispatch: the recipient user matches the pinned designated
// recipient and both the recipient provider and the receiver domain normalize
// to the run's target host.
func (s *Service) requestMatchesDesignated(
	req sharesoutgoing.OutgoingShareRequest,
	run *validatorcore.TestRun,
	designated string,
) bool {
	user, provider, err := address.Parse(req.ShareWith)
	if err != nil {
		return false
	}

	providerNormalized, err := hostport.Normalize(provider, s.deps.LocalIdentity.Scheme)
	if err != nil || providerNormalized != run.TargetHost {
		return false
	}

	if user+"@"+providerNormalized != designated {
		return false
	}

	receiverNormalized, err := hostport.Normalize(req.ReceiverDomain, s.deps.LocalIdentity.Scheme)
	if err != nil {
		return false
	}

	return receiverNormalized == run.TargetHost
}

// requestMatchesReservation reports whether the request matches the
// reservation snapshot: normalized recipient, receiver host, and the cleaned
// probe path.
func (s *Service) requestMatchesReservation(
	req sharesoutgoing.OutgoingShareRequest,
	reservation *validatorcore.DispatchReservation,
) bool {
	user, provider, err := address.Parse(req.ShareWith)
	if err != nil {
		return false
	}

	providerNormalized, err := hostport.Normalize(provider, s.deps.LocalIdentity.Scheme)
	if err != nil || user+"@"+providerNormalized != reservation.ShareWith {
		return false
	}

	receiverNormalized, err := hostport.Normalize(req.ReceiverDomain, s.deps.LocalIdentity.Scheme)
	if err != nil || receiverNormalized != reservation.ReceiverHost {
		return false
	}

	return filepath.Clean(req.LocalPath) == reservation.ProbeFilePath
}

// mintClaimToken generates the owner fence for one send permit. The token is
// a random UUID, so a reclaimed permit's new owner can never be guessed by
// the fenced stale owner.
func mintClaimToken() (string, error) {
	token, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("forwardshare: mint claim token: %w", err)
	}

	return token.String(), nil
}
