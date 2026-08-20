// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"gorm.io/gorm"
)

// Evidence tuple written by the winning reverse-invite accept CAS. The
// reverse leg keeps the fact out of the capability-exercise advance path.
const (
	evidenceAreaReverseInvite     = "reverse_invite"
	evidenceStepInviteAccepted    = "invite_accepted"
	evidenceReasonReverseAccepted = "reverse_invite_accepted"
)

// Column names for the reverse-invite leg fields, so the CAS update maps stay
// in lockstep with the schema contract and retention wipe list.
const (
	colDesignatedShareWith     = "designated_share_with"
	colReverseInviteToken      = "reverse_invite_token"
	colReverseInviteImportedAt = "reverse_invite_imported_at"
)

// statesAtOrPastInviteAccepted lists active states that already carry the
// outgoing invite_accepted observation, so re-observing acceptance is a no-op.
var statesAtOrPastInviteAccepted = []string{
	StateInviteAccepted,
	StateReverseInviteSolicited,
	StateReverseAwaitingInvite,
	StateReverseInviteImported,
	StateReverseInviteAccepted,
	StateForwardShareSent,
	StateCapabilityExercise,
	StateReverseAwaitingShare,
}

// statesAtOrPastAwaitingInvite lists active states that already passed the
// reverse_invite_solicited -> reverse_awaiting_invite CAS.
var statesAtOrPastAwaitingInvite = []string{
	StateReverseAwaitingInvite,
	StateReverseInviteImported,
	StateReverseInviteAccepted,
	StateForwardShareSent,
	StateCapabilityExercise,
	StateReverseAwaitingShare,
}

// statesAtOrPastInviteImported lists active states that already passed the
// reverse_awaiting_invite -> reverse_invite_imported CAS.
var statesAtOrPastInviteImported = []string{
	StateReverseInviteImported,
	StateReverseInviteAccepted,
	StateForwardShareSent,
	StateCapabilityExercise,
	StateReverseAwaitingShare,
}

// statesAtOrPastReverseInviteAccepted lists states that already passed the
// reverse_invite_imported -> reverse_invite_accepted CAS, so a repeated
// accept is a no-op that must not re-accept or regress the run. Terminal
// fail and interrupted are excluded on purpose: they are reachable from any
// state, so they prove nothing about the accept having happened.
var statesAtOrPastReverseInviteAccepted = []string{
	StateReverseInviteAccepted,
	StateForwardShareSent,
	StateCapabilityExercise,
	StateReverseAwaitingShare,
	StateTerminalPass,
}

func stateIn(state string, set []string) bool {
	return slices.Contains(set, state)
}

// MintOutgoingInviteBinding atomically compare-and-binds the run's
// RoleOutgoingInvite correlation slot and CASes active_running ->
// invite_minted in one transaction. Retrying with the same invite ID and
// token is idempotent; a different ID or token, or more than one row in the
// slot, is a conflict. Concurrent mints race to exactly one winner.
func (c *Core) MintOutgoingInviteBinding(ctx context.Context, testRunID, inviteID, token string) error {
	if testRunID == "" || inviteID == "" || token == "" {
		return errors.New("validatorcore: mint outgoing invite binding requires run id, invite id, and token")
	}

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return mintOutgoingInviteTx(tx, testRunID, inviteID, token, time.Now().Unix())
	})
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrDuplicatedKey) {
		// A concurrent mint claimed the slot first; classify idempotent vs
		// conflict from the winner's row.
		return c.classifyOutgoingSlotRace(ctx, testRunID, inviteID, token, err)
	}

	return fmt.Errorf("validatorcore: mint outgoing invite binding: %w", err)
}

// mintOutgoingInviteTx is the transaction body of MintOutgoingInviteBinding:
// prove the slot is free or identically bound, claim it, then CAS the state.
func mintOutgoingInviteTx(tx *gorm.DB, testRunID, inviteID, token string, now int64) error {
	var run TestRun
	if err := tx.First(&run, "test_run_id = ?", testRunID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrSessionNotFound
		}

		return fmt.Errorf("validatorcore: load test run: %w", err)
	}

	existing, err := listShareCorrelationsTx(tx, testRunID, RoleOutgoingInvite)
	if err != nil {
		return err
	}

	switch len(existing) {
	case 0:
		// Slot is free; claim it below.
	case 1:
		row := existing[0]
		if stringPtrEqual(row.InviteID, inviteID) && row.ProviderID == token {
			return nil
		}

		return ErrShareCorrelationConflict
	default:
		return ErrShareCorrelationConflict
	}

	corr := ShareCorrelation{
		TestRunID:     testRunID,
		Role:          RoleOutgoingInvite,
		LocalIdentity: LocalIdentityA,
		SenderHost:    run.TargetHost,
		InviteID:      &inviteID,
		ProviderID:    token,
		Status:        CorrelationStatusConfirmed,
		CreatedAt:     now,
	}
	if err := tx.Create(&corr).Error; err != nil {
		return fmt.Errorf("validatorcore: bind outgoing invite slot: %w", err)
	}

	res := tx.Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = 1 AND state = ?", testRunID, StateActiveRunning).
		Updates(map[string]any{
			colState:     StateInviteMinted,
			colUpdatedAt: now,
		})
	if res.Error != nil {
		return fmt.Errorf("validatorcore: mint outgoing invite CAS: %w", res.Error)
	}

	if res.RowsAffected == 0 {
		return ErrStateTransitionMiss
	}

	return nil
}

func (c *Core) classifyOutgoingSlotRace(ctx context.Context, testRunID, inviteID, token string, original error) error {
	row, err := c.GetShareCorrelation(ctx, testRunID, RoleOutgoingInvite, LocalIdentityA)
	if err != nil {
		return original
	}

	if stringPtrEqual(row.InviteID, inviteID) && row.ProviderID == token {
		return nil
	}

	return ErrShareCorrelationConflict
}

// RecordOutgoingInviteAccepted CASes invite_minted -> invite_accepted and
// pins designated_share_with. Re-observing acceptance from a later state is
// an idempotent no-op; any other miss is a transition error.
func (c *Core) RecordOutgoingInviteAccepted(ctx context.Context, testRunID, shareWith string) error {
	if testRunID == "" {
		return errors.New("validatorcore: empty test run id")
	}

	now := time.Now().Unix()

	res := c.db.WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = 1 AND state = ?", testRunID, StateInviteMinted).
		Updates(map[string]any{
			colState:               StateInviteAccepted,
			colUpdatedAt:           now,
			colDesignatedShareWith: shareWith,
		})
	if res.Error != nil {
		return fmt.Errorf("validatorcore: record outgoing invite accepted: %w", res.Error)
	}

	if res.RowsAffected > 0 {
		return nil
	}

	run, err := c.GetTestRun(ctx, testRunID)
	if err != nil {
		return err
	}

	if stateIn(run.State, statesAtOrPastInviteAccepted) {
		return nil
	}

	return ErrStateTransitionMiss
}

// SolicitReverse advances invite_accepted -> reverse_invite_solicited and
// then reverse_invite_solicited -> reverse_awaiting_invite as two separate
// CASes. A first-CAS miss on an already-solicited run heals the crash notch
// by running the second CAS; a run already awaiting (or past) is idempotent.
func (c *Core) SolicitReverse(ctx context.Context, testRunID string) error {
	if testRunID == "" {
		return errors.New("validatorcore: empty test run id")
	}

	now := time.Now().Unix()

	res := c.db.WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = 1 AND state = ?", testRunID, StateInviteAccepted).
		Updates(map[string]any{
			colState:     StateReverseInviteSolicited,
			colUpdatedAt: now,
		})
	if res.Error != nil {
		return fmt.Errorf("validatorcore: solicit reverse CAS: %w", res.Error)
	}

	if res.RowsAffected == 0 {
		run, err := c.GetTestRun(ctx, testRunID)
		if err != nil {
			return err
		}

		switch {
		case run.State == StateReverseInviteSolicited:
			// Crash notch: the first CAS committed but the second never ran.
		case stateIn(run.State, statesAtOrPastAwaitingInvite):
			return nil
		default:
			return ErrStateTransitionMiss
		}
	}

	res = c.db.WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = 1 AND state = ?", testRunID, StateReverseInviteSolicited).
		Updates(map[string]any{
			colState:     StateReverseAwaitingInvite,
			colUpdatedAt: now,
		})
	if res.Error != nil {
		return fmt.Errorf("validatorcore: await reverse invite CAS: %w", res.Error)
	}

	if res.RowsAffected > 0 {
		return nil
	}

	run, err := c.GetTestRun(ctx, testRunID)
	if err != nil {
		return err
	}

	if stateIn(run.State, statesAtOrPastAwaitingInvite) {
		return nil
	}

	return ErrStateTransitionMiss
}

// ImportReverseInvite atomically binds the run's RoleIncomingInvite slot and
// CASes reverse_awaiting_invite -> reverse_invite_imported in one
// transaction. The first imported token wins: a retry with the same token and
// invite ID is idempotent, a different token after occupancy is a conflict
// with no state advance.
func (c *Core) ImportReverseInvite(ctx context.Context, testRunID, token, inviteID string) error {
	if testRunID == "" || token == "" || inviteID == "" {
		return errors.New("validatorcore: import reverse invite requires run id, token, and invite id")
	}

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return importReverseInviteTx(tx, testRunID, token, inviteID, time.Now().Unix())
	})
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return c.classifyIncomingSlotRace(ctx, testRunID, token, inviteID, err)
	}

	return fmt.Errorf("validatorcore: import reverse invite: %w", err)
}

// importReverseInviteTx is the transaction body of ImportReverseInvite: prove
// the incoming slot is free or identically bound, claim it, then CAS the
// state and pin the imported token.
func importReverseInviteTx(tx *gorm.DB, testRunID, token, inviteID string, now int64) error {
	var run TestRun
	if err := tx.First(&run, "test_run_id = ?", testRunID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrSessionNotFound
		}

		return fmt.Errorf("validatorcore: load test run: %w", err)
	}

	existing, err := listShareCorrelationsTx(tx, testRunID, RoleIncomingInvite)
	if err != nil {
		return err
	}

	switch len(existing) {
	case 0:
		// Slot is free; claim it below.
	case 1:
		row := existing[0]
		if row.ProviderID != token || !stringPtrEqual(row.InviteID, inviteID) {
			return ErrShareCorrelationConflict
		}

		if stateIn(run.State, statesAtOrPastInviteImported) {
			return nil
		}

		return ErrStateTransitionMiss
	default:
		return ErrShareCorrelationConflict
	}

	corr := ShareCorrelation{
		TestRunID:     testRunID,
		Role:          RoleIncomingInvite,
		LocalIdentity: LocalIdentityB,
		SenderHost:    run.TargetHost,
		InviteID:      &inviteID,
		ProviderID:    token,
		Status:        CorrelationStatusConfirmed,
		CreatedAt:     now,
	}
	if err := tx.Create(&corr).Error; err != nil {
		return fmt.Errorf("validatorcore: bind incoming invite slot: %w", err)
	}

	res := tx.Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = 1 AND state = ? AND "+colReverseInviteToken+" IS NULL", testRunID, StateReverseAwaitingInvite).
		Updates(map[string]any{
			colState:                   StateReverseInviteImported,
			colUpdatedAt:               now,
			colReverseInviteToken:      token,
			colReverseInviteImportedAt: now,
		})
	if res.Error != nil {
		return fmt.Errorf("validatorcore: import reverse invite CAS: %w", res.Error)
	}

	if res.RowsAffected == 0 {
		return ErrStateTransitionMiss
	}

	return nil
}

func (c *Core) classifyIncomingSlotRace(ctx context.Context, testRunID, token, inviteID string, original error) error {
	row, err := c.GetShareCorrelation(ctx, testRunID, RoleIncomingInvite, LocalIdentityB)
	if err != nil {
		return original
	}

	if row.ProviderID != token || !stringPtrEqual(row.InviteID, inviteID) {
		return ErrShareCorrelationConflict
	}

	run, err := c.GetTestRun(ctx, testRunID)
	if err != nil {
		return original
	}

	if stateIn(run.State, statesAtOrPastInviteImported) {
		return nil
	}

	return ErrStateTransitionMiss
}

// AcceptReverseInvite CASes reverse_invite_imported -> reverse_invite_accepted
// and, only on the winning CAS, writes the reverse-invite accept evidence
// tuple through the shared evidence seam in the same transaction. A miss on
// a run already at or past reverse_invite_accepted is idempotent success that
// leaves the later state untouched; any other miss is a transition error.
func (c *Core) AcceptReverseInvite(ctx context.Context, testRunID string) error {
	if testRunID == "" {
		return errors.New("validatorcore: empty test run id")
	}

	now := time.Now().Unix()

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&TestRun{}).
			Where("test_run_id = ? AND is_active = 1 AND state = ?", testRunID, StateReverseInviteImported).
			Updates(map[string]any{
				colState:     StateReverseInviteAccepted,
				colUpdatedAt: now,
			})
		if res.Error != nil {
			return fmt.Errorf("validatorcore: accept reverse invite CAS: %w", res.Error)
		}

		if res.RowsAffected == 0 {
			return ErrStateTransitionMiss
		}

		return applyEvidenceFactTx(tx, ApplyEvidenceFactInput{
			TestRunID:    testRunID,
			Area:         evidenceAreaReverseInvite,
			Step:         evidenceStepInviteAccepted,
			ReasonCode:   evidenceReasonReverseAccepted,
			Severity:     GradePass,
			AffectsGrade: true,
			Leg:          evidenceLegReverse,
		}, now)
	})
	if err == nil {
		return nil
	}

	if !errors.Is(err, ErrStateTransitionMiss) {
		return fmt.Errorf("validatorcore: accept reverse invite: %w", err)
	}

	run, loadErr := c.GetTestRun(ctx, testRunID)
	if loadErr != nil {
		return loadErr
	}

	// A run already at or past reverse_invite_accepted keeps its state; the
	// repeated accept is idempotent success and must not regress it.
	if stateIn(run.State, statesAtOrPastReverseInviteAccepted) {
		return nil
	}

	return fmt.Errorf("validatorcore: accept reverse invite: %w", err)
}
