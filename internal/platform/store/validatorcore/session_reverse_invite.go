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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// Evidence tuple written by the winning reverse-invite paste. The reverse
// leg keeps the fact out of the capability-exercise advance path.
const (
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
	StateReverseAwaitingInvite,
	StateReverseInviteAccepted,
	StateForwardShareSent,
	StateCapabilityExercise,
	StateReverseAwaitingShare,
}

// statesAtOrPastAwaitingInvite lists active states that already passed the
// invite_accepted -> reverse_awaiting_invite CAS.
var statesAtOrPastAwaitingInvite = []string{
	StateReverseAwaitingInvite,
	StateReverseInviteAccepted,
	StateForwardShareSent,
	StateCapabilityExercise,
	StateReverseAwaitingShare,
}

// statesAtOrPastReverseInviteAccepted lists states that already passed the
// reverse_awaiting_invite -> reverse_invite_accepted paste, so a repeated
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

func reverseInviteAcceptEvidence(testRunID string) ApplyEvidenceFactInput {
	return ApplyEvidenceFactInput{
		TestRunID:    testRunID,
		Area:         SpecificationAreaSharing,
		Step:         evidenceStepInviteAccepted,
		ReasonCode:   evidenceReasonReverseAccepted,
		Severity:     GradePass,
		AffectsGrade: true,
		Leg:          evidenceLegReverse,
	}
}

// OutgoingInviteMint is the product-row payload written in the same
// transaction as the run pointer bind and invite_minted CAS.
type OutgoingInviteMint struct {
	ID              string
	Token           string
	ProviderFQDN    string
	InviteString    string
	CreatedByUserID string
	Status          string
	CreatedAt       int64
	ExpiresAt       int64
}

// MintOutgoingInvite inserts the product outgoing invite, binds
// outgoing_invite_id, and CASes active_running -> invite_minted in one
// transaction on the shared handle. Retrying with the same invite ID is
// idempotent and does not write s1_claimed_at. A different ID is a
// conflict. The invite token is stored only on the product row.
func (c *Core) MintOutgoingInvite(ctx context.Context, testRunID string, invite OutgoingInviteMint) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if testRunID == "" || invite.ID == "" || invite.Token == "" {
		return errors.New("validatorcore: mint outgoing invite requires run id, invite id, and token")
	}

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return mintOutgoingInviteTx(tx, testRunID, invite, time.Now().Unix())
	})
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return c.classifyOutgoingInviteRace(ctx, testRunID, invite.ID, err)
	}

	return fmt.Errorf("validatorcore: mint outgoing invite: %w", err)
}

func mintOutgoingInviteTx(tx *gorm.DB, testRunID string, invite OutgoingInviteMint, now int64) error {
	run, err := loadTestRunTx(tx, testRunID)
	if err != nil {
		return err
	}

	skip, precheckErr := outgoingMintSkipOrErr(run, invite.ID)
	if precheckErr != nil {
		return precheckErr
	}

	if skip {
		return nil
	}

	if insertErr := insertOutgoingInviteTx(tx, invite, now); insertErr != nil {
		return insertErr
	}

	if bindErr := bindOutgoingInviteTx(tx, testRunID, invite.ID, now); bindErr != nil {
		return bindErr
	}

	return casInviteMintedTx(tx, testRunID, now)
}

func loadTestRunTx(tx *gorm.DB, testRunID string) (*TestRun, error) {
	var run TestRun

	if err := tx.First(&run, "test_run_id = ?", testRunID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSessionNotFound
		}

		return nil, fmt.Errorf("validatorcore: load test run: %w", err)
	}

	return &run, nil
}

func outgoingMintSkipOrErr(run *TestRun, inviteID string) (skip bool, err error) {
	if run.OutgoingInviteID != nil && *run.OutgoingInviteID != "" {
		if *run.OutgoingInviteID == inviteID {
			return true, nil
		}

		return false, ErrShareCorrelationConflict
	}

	if !run.IsActive || run.State != StateActiveRunning {
		return false, ErrStateTransitionMiss
	}

	return false, nil
}

func insertOutgoingInviteTx(tx *gorm.DB, invite OutgoingInviteMint, now int64) error {
	if err := invites.ValidateCreateInviteStatus(invite.Status, "", ""); err != nil {
		return fmt.Errorf("validatorcore: validate outgoing invite: %w", err)
	}

	row := store.OutgoingInvite{
		ID:              invite.ID,
		Token:           invite.Token,
		ProviderFQDN:    invite.ProviderFQDN,
		InviteString:    invite.InviteString,
		CreatedByUserID: invite.CreatedByUserID,
		Status:          invite.Status,
		CreatedAt:       invite.CreatedAt,
		ExpiresAt:       invite.ExpiresAt,
		UpdatedAt:       now,
	}
	if err := tx.Create(&row).Error; err != nil {
		return err
	}

	return nil
}

func bindOutgoingInviteTx(tx *gorm.DB, testRunID, inviteID string, now int64) error {
	res := tx.Model(&TestRun{}).
		Where("test_run_id = ? AND "+colOutgoingInviteID+" IS NULL", testRunID).
		Updates(map[string]any{
			colOutgoingInviteID: inviteID,
			colUpdatedAt:        now,
		})
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrDuplicatedKey) {
			return res.Error
		}

		return fmt.Errorf("validatorcore: bind outgoing invite: %w", res.Error)
	}

	if res.RowsAffected == 0 {
		return gorm.ErrDuplicatedKey
	}

	return nil
}

func casInviteMintedTx(tx *gorm.DB, testRunID string, now int64) error {
	cas := tx.Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = 1 AND state = ?", testRunID, StateActiveRunning).
		Updates(map[string]any{
			colState:     StateInviteMinted,
			colUpdatedAt: now,
		})
	if cas.Error != nil {
		return fmt.Errorf("validatorcore: mint outgoing invite CAS: %w", cas.Error)
	}

	if cas.RowsAffected == 0 {
		return ErrStateTransitionMiss
	}

	return nil
}

func (c *Core) classifyOutgoingInviteRace(ctx context.Context, testRunID, inviteID string, original error) error {
	run, err := c.GetTestRun(ctx, testRunID)
	if err != nil {
		return NewStoreError(OpMintOutgoingInvite, original)
	}

	if run.OutgoingInviteID != nil && *run.OutgoingInviteID == inviteID {
		return nil
	}

	if run.OutgoingInviteID != nil && *run.OutgoingInviteID != "" {
		return ErrShareCorrelationConflict
	}

	return NewStoreError(OpMintOutgoingInvite, original)
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

// SolicitReverse CASes invite_accepted -> reverse_awaiting_invite. A run
// already awaiting (or past) is idempotent.
func (c *Core) SolicitReverse(ctx context.Context, testRunID string) error {
	if testRunID == "" {
		return errors.New("validatorcore: empty test run id")
	}

	now := time.Now().Unix()

	res := c.db.WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = 1 AND state = ?", testRunID, StateInviteAccepted).
		Updates(map[string]any{
			colState:     StateReverseAwaitingInvite,
			colUpdatedAt: now,
		})
	if res.Error != nil {
		return fmt.Errorf("validatorcore: solicit reverse CAS: %w", res.Error)
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

// ImportReverseInvite binds the run's RoleIncomingInvite slot and CASes
// reverse_awaiting_invite -> reverse_invite_accepted in one transaction,
// writing sharing-area accept evidence on the winning paste. The first
// imported token wins: a retry with the same token and invite ID is
// idempotent, a different token after occupancy is a conflict with no
// state advance.
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

		if stateIn(run.State, statesAtOrPastReverseInviteAccepted) {
			return applyEvidenceFactTx(tx, reverseInviteAcceptEvidence(testRunID), now)
		}

		if run.State != StateReverseAwaitingInvite {
			return ErrStateTransitionMiss
		}
	default:
		return ErrShareCorrelationConflict
	}

	if len(existing) == 0 {
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
	}

	res := tx.Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = 1 AND state = ? AND "+colReverseInviteToken+" IS NULL", testRunID, StateReverseAwaitingInvite).
		Updates(map[string]any{
			colState:                   StateReverseInviteAccepted,
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

	return applyEvidenceFactTx(tx, reverseInviteAcceptEvidence(testRunID), now)
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

	if stateIn(run.State, statesAtOrPastReverseInviteAccepted) {
		return nil
	}

	return ErrStateTransitionMiss
}

// AcceptReverseInvite is idempotent once the paste has already landed the
// run at or past reverse_invite_accepted. A run still awaiting the paste
// (or in any other unmatched state) is a transition miss. The paste itself
// lives in ImportReverseInvite.
func (c *Core) AcceptReverseInvite(ctx context.Context, testRunID string) error {
	if testRunID == "" {
		return errors.New("validatorcore: empty test run id")
	}

	run, err := c.GetTestRun(ctx, testRunID)
	if err != nil {
		return err
	}

	if stateIn(run.State, statesAtOrPastReverseInviteAccepted) {
		return nil
	}

	return fmt.Errorf("validatorcore: accept reverse invite: %w", ErrStateTransitionMiss)
}
