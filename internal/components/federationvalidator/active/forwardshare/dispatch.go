// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package forwardshare

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	ocmshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// statesAtOrPastForwardShareSent lists the states a run can hold after the
// forward-share commit CAS landed; re-committing from any of them is an
// idempotent no-op. terminal_fail and interrupted are reachable from any
// state, so they prove nothing about the commit and are handled separately.
var statesAtOrPastForwardShareSent = []string{
	validatorcore.StateForwardShareSent,
	validatorcore.StateCapabilityExercise,
	validatorcore.StateReverseAwaitingShare,
	validatorcore.StateTerminalPass,
}

// NoteWireURI implements the dispatch hook's wire-identity snapshot seat: the
// reservation records the exact WebDAV URI the handler is about to send, so a
// later retry replays it instead of rebuilding from possibly drifted
// discovery.
func (s *Service) NoteWireURI(ctx context.Context, plan *outgoingshares.DispatchPlan, webdavURI string) error {
	if plan == nil {
		return nil
	}

	if err := s.deps.Store.SnapshotForwardDispatchWireURI(ctx, plan.TestRunID, plan.ProviderID, plan.ClaimToken, webdavURI); err != nil {
		return fmt.Errorf("forwardshare: snapshot wire uri: %w", err)
	}

	return nil
}

// CheckSendClaim implements the dispatch hook's pre-send ownership check: the
// planned dispatch must still own the send permit when the handler is about
// to post, so a fenced stale plan never reaches the receiver.
func (s *Service) CheckSendClaim(ctx context.Context, plan *outgoingshares.DispatchPlan) error {
	if plan == nil {
		return nil
	}

	if err := s.deps.Store.CheckForwardDispatchClaim(ctx, plan.TestRunID, plan.ProviderID, plan.ClaimToken); err != nil {
		return fmt.Errorf("forwardshare: check send claim: %w", err)
	}

	return nil
}

// AbortSend implements the dispatch hook's permit-release seat: a planned
// dispatch that will not complete its send returns the permit to reserved, so
// a later attempt can retry with the same provider identity and snapshotted
// payload. A reservation that already recorded the remote send is left for
// the replay path. A fenced stale owner is told its claim is gone; that is
// the intended outcome of the reclaim, not a failure.
func (s *Service) AbortSend(ctx context.Context, plan *outgoingshares.DispatchPlan) error {
	if plan == nil {
		return nil
	}

	err := s.deps.Store.ReleaseForwardDispatchClaim(ctx, plan.TestRunID, plan.ProviderID, plan.ClaimToken)
	if errors.Is(err, validatorcore.ErrDispatchClaimLost) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("forwardshare: release dispatch claim: %w", err)
	}

	return nil
}

// CommitSent implements the dispatch hook's post-delivery seat: stamp the
// reservation remote_sent, run the conjunctive commit CAS, then presence-heal
// the capability advance. The hook runs after the outbound POST succeeded and
// before the handler's success response, so a replay never answers before the
// heal had its chance.
func (s *Service) CommitSent(ctx context.Context, plan *outgoingshares.DispatchPlan, share *sharesoutgoing.OutgoingShare) error {
	if plan == nil {
		return nil
	}

	if err := s.deps.Store.MarkForwardDispatchRemoteSent(ctx, plan.TestRunID, plan.ProviderID, plan.ClaimToken, share.ShareID); err != nil {
		return fmt.Errorf("forwardshare: mark remote sent: %w", err)
	}

	run, reservation, err := s.loadRunAndReservation(ctx, plan.TestRunID)
	if err != nil {
		return err
	}

	// The plan carries the exact URI this attempt put on the wire; the commit
	// CAS proves it against the reservation snapshot.
	return s.commitAndHeal(ctx, run, reservation, plan.WebDAVURI, share.ShareID)
}

// replay reconciles an already-sent dispatch without a second outbound POST:
// commit when the first attempt crashed between the send and the CAS,
// presence-heal the capability advance, reconcile the local row's delivery
// status, then answer from the stored share snapshot.
func (s *Service) replay(
	ctx context.Context,
	run *validatorcore.TestRun,
	reservation *validatorcore.DispatchReservation,
) (*outgoingshares.DispatchPlan, error) {
	share, err := s.deps.OutgoingShares.GetByProviderID(ctx, reservation.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("forwardshare: load dispatched share: %w", err)
	}

	// The replay commits against the exact stored wire URI snapshot.
	if err := s.commitAndHeal(ctx, run, reservation, reservation.WebDAVID, share.ShareID); err != nil {
		return nil, err
	}

	if err := s.reconcileLocalSent(ctx, share); err != nil {
		return nil, err
	}

	return &outgoingshares.DispatchPlan{
		TestRunID:    run.TestRunID,
		ProviderID:   reservation.ProviderID,
		WebDAVID:     share.WebDAVID,
		SharedSecret: reservation.SharedSecret,
		ReplayShare:  share,
	}, nil
}

// commitAndHeal runs the commit CAS unless a previous attempt already
// committed, then presence-heals the capability advance. A capability
// observation may have landed between delivery and the commit, so the heal
// always runs before the handler answers.
func (s *Service) commitAndHeal(
	ctx context.Context,
	run *validatorcore.TestRun,
	reservation *validatorcore.DispatchReservation,
	webdavURI string,
	outgoingShareID string,
) error {
	if err := s.recordOutgoingShare(ctx, run.TestRunID); err != nil {
		return err
	}

	if reservation.CASCommittedAt == nil {
		if err := s.commitForwardShareSent(ctx, run, reservation, webdavURI, outgoingShareID); err != nil {
			return err
		}
	}

	if err := s.deps.Store.HealForwardSharePresence(ctx, run.TestRunID); err != nil {
		return fmt.Errorf("forwardshare: heal capability presence: %w", err)
	}

	return nil
}

// reconcileLocalSent brings the local row's delivery status in line with the
// recorded remote success. A first attempt whose local sent stamp failed
// after the commit leaves the row pending; the replay repairs it without a
// second outbound POST.
func (s *Service) reconcileLocalSent(ctx context.Context, share *sharesoutgoing.OutgoingShare) error {
	if share.Status == ocmshares.OutgoingShareStatusSent {
		return nil
	}

	share.Status = ocmshares.OutgoingShareStatusSent
	share.Error = ""

	if share.SentAt == nil {
		sentAt := time.Now()
		share.SentAt = &sentAt
	}

	if err := s.deps.OutgoingShares.Update(ctx, share); err != nil {
		return fmt.Errorf("forwardshare: reconcile local sent status: %w", err)
	}

	return nil
}

// commitForwardShareSent runs the conjunctive commit CAS. A miss on a run
// already at or past forward_share_sent is idempotent success; a miss on a
// terminalized run leaves the terminal state alone; any other active state
// means the run can no longer commit after a recorded remote send, so it is
// interrupted through the shared active-terminal writer seam, never failed.
func (s *Service) commitForwardShareSent(
	ctx context.Context,
	run *validatorcore.TestRun,
	reservation *validatorcore.DispatchReservation,
	webdavURI string,
	outgoingShareID string,
) error {
	designated, ok := s.designatedShareWith(run)
	if !ok {
		return errors.New("forwardshare: run has no usable designated recipient")
	}

	err := s.deps.Store.CommitForwardShareSent(ctx, validatorcore.ForwardShareCommit{
		TestRunID:           run.TestRunID,
		ProviderID:          reservation.ProviderID,
		ReceiverHost:        run.TargetHost,
		ShareWith:           designated,
		DesignatedShareWith: *run.DesignatedShareWith,
		ProbeFilePath:       reservation.ProbeFilePath,
		WebDAVURI:           webdavURI,
		OutgoingShareID:     outgoingShareID,
	})
	if err == nil {
		return nil
	}

	if !errors.Is(err, validatorcore.ErrStateTransitionMiss) && !errors.Is(err, validatorcore.ErrDispatchNotSent) {
		return fmt.Errorf("forwardshare: commit forward share sent: %w", err)
	}

	// ErrDispatchNotSent from a replay means a concurrent dispatcher's commit
	// landed between the reservation load and this CAS; the reload inside
	// classifies the run state and treats the committed run as idempotent
	// success.
	return s.classifyCommitMiss(ctx, run.TestRunID)
}

func (s *Service) recordOutgoingShare(ctx context.Context, testRunID string) error {
	if err := s.deps.Store.PersistActiveExchangeAndFact(
		ctx,
		validatorcore.OutgoingSharesExchange(testRunID),
		validatorcore.ForwardShareSentFact(testRunID, nil),
	); err != nil {
		return fmt.Errorf("forwardshare: record outgoing share: %w", err)
	}

	return nil
}

// classifyCommitMiss decides what a commit CAS miss means from the run's
// current state.
func (s *Service) classifyCommitMiss(ctx context.Context, testRunID string) error {
	current, err := s.deps.Store.GetTestRun(ctx, testRunID)
	if err != nil {
		return fmt.Errorf("forwardshare: reload run after commit miss: %w", err)
	}

	if slices.Contains(statesAtOrPastForwardShareSent, current.State) {
		return nil
	}

	if !current.IsActive || isTerminalState(current.State) {
		// Already terminalized by another path; leave the terminal state alone.
		return nil
	}

	// The remote send is recorded but the run can no longer commit: interrupt
	// through the shared active-terminal writer (best-effort stats included),
	// never as a hard fail.
	interruptErr := s.deps.Store.ReleaseActiveTerminalFrom(ctx, testRunID, []string{current.State}, validatorcore.ActiveTerminalUpdate{
		State:          validatorcore.StateInterrupted,
		TerminalReason: validatorcore.ReasonForwardShareCommitStall,
	})
	if interruptErr != nil && !errors.Is(interruptErr, validatorcore.ErrStateTransitionMiss) {
		return fmt.Errorf("forwardshare: interrupt after commit miss: %w", interruptErr)
	}

	return errors.New("forwardshare: run interrupted after recorded remote send")
}

func (s *Service) loadRunAndReservation(
	ctx context.Context,
	testRunID string,
) (*validatorcore.TestRun, *validatorcore.DispatchReservation, error) {
	run, err := s.deps.Store.GetTestRun(ctx, testRunID)
	if err != nil {
		return nil, nil, fmt.Errorf("forwardshare: load run: %w", err)
	}

	reservation, err := s.deps.Store.GetDispatchReservation(ctx, testRunID)
	if err != nil {
		return nil, nil, fmt.Errorf("forwardshare: load reservation: %w", err)
	}

	return run, reservation, nil
}

func isTerminalState(state string) bool {
	switch state {
	case validatorcore.StateTerminalPass, validatorcore.StateTerminalFail, validatorcore.StateInterrupted:
		return true
	default:
		return false
	}
}

// generateSharedSecret mirrors the generic handler's secret format so a
// reserved dispatch is indistinguishable on the wire.
func generateSharedSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("forwardshare: generate shared secret: %w", err)
	}

	return base64.URLEncoding.EncodeToString(b), nil
}
