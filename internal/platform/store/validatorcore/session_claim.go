// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// ClaimedOutgoingInvite is the one-time session-invite disclosure payload.
// It carries only the fields the operator needs to paste the invite; the
// raw token stays on the product row and is never copied here.
type ClaimedOutgoingInvite struct {
	InviteString      string
	IssuerFQDN        string
	PasteTargetOrigin string
	PasteTargetHost   string
	ExpiresAt         time.Time
}

// SetClaimPayloadLoadHook installs a test seam invoked while loading the
// outgoing invite row inside the claim transaction. A non-nil error
// rolls the transaction back so s1_claimed_at is not written.
func (c *Core) SetClaimPayloadLoadHook(fn func() error) {
	if c == nil {
		return
	}

	c.claimPayloadLoadHook = fn
}

// ClaimOutgoingInvite CASes the one-time session invite claim in one
// transaction: verify s1_claimed_at IS NULL, state invite_minted, and
// is_active=1; load the outgoing invite payload; then write
// s1_claimed_at. A payload-load failure rolls back so the claim stays
// available. A miss inspects s1_claimed_at before state so a
// later-state second claim is already-claimed rather than not-ready.
// The write never remints.
func (c *Core) ClaimOutgoingInvite(ctx context.Context, testRunID string) (*ClaimedOutgoingInvite, error) {
	if c == nil || c.db == nil {
		return nil, errors.New("validatorcore: store is not configured")
	}

	if testRunID == "" {
		return nil, ErrSessionNotFound
	}

	now := time.Now().Unix()

	var claimed *ClaimedOutgoingInvite

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		payload, txErr := c.claimOutgoingInviteTx(tx, testRunID, now)
		if txErr != nil {
			return txErr
		}

		claimed = payload

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("validatorcore: claim outgoing invite: %w", err)
	}

	return claimed, nil
}

func (c *Core) claimOutgoingInviteTx(
	tx *gorm.DB,
	testRunID string,
	now int64,
) (*ClaimedOutgoingInvite, error) {
	run, err := loadTestRunTx(tx, testRunID)
	if err != nil {
		return nil, err
	}

	if miss := classifyOutgoingInviteClaimMiss(run); miss != nil {
		return nil, miss
	}

	payload, loadErr := c.loadClaimedOutgoingInviteTx(tx, run)
	if loadErr != nil {
		return nil, loadErr
	}

	res := tx.Model(&TestRun{}).
		Where(
			"test_run_id = ? AND "+colS1ClaimedAt+" IS NULL AND is_active = 1 AND state = ?",
			testRunID,
			StateInviteMinted,
		).
		Updates(map[string]any{
			colS1ClaimedAt: now,
			colUpdatedAt:   now,
		})
	if res.Error != nil {
		return nil, fmt.Errorf("validatorcore: claim outgoing invite: %w", res.Error)
	}

	if res.RowsAffected == 0 {
		return nil, classifyOutgoingInviteClaimCASMiss(tx, testRunID)
	}

	return payload, nil
}

func classifyOutgoingInviteClaimCASMiss(tx *gorm.DB, testRunID string) error {
	run, err := loadTestRunTx(tx, testRunID)
	if err != nil {
		return err
	}

	if miss := classifyOutgoingInviteClaimMiss(run); miss != nil {
		return miss
	}

	return ErrStateTransitionMiss
}

func classifyOutgoingInviteClaimMiss(run *TestRun) error {
	if run.S1ClaimedAt != nil {
		return ErrInviteAlreadyClaimed
	}

	if !run.IsActive || run.State != StateInviteMinted {
		return ErrSessionNotReady
	}

	return nil
}

func (c *Core) loadClaimedOutgoingInviteTx(tx *gorm.DB, run *TestRun) (*ClaimedOutgoingInvite, error) {
	if hook := c.claimPayloadLoadHook; hook != nil {
		if hookErr := hook(); hookErr != nil {
			return nil, fmt.Errorf("validatorcore: load claimed outgoing invite: %w", hookErr)
		}
	}

	if run.OutgoingInviteID == nil || *run.OutgoingInviteID == "" {
		return nil, errors.New("validatorcore: claimed run has no outgoing invite")
	}

	var row store.OutgoingInvite

	loadErr := tx.First(&row, "id = ?", *run.OutgoingInviteID).Error
	if loadErr != nil {
		return nil, fmt.Errorf("validatorcore: load claimed outgoing invite: %w", loadErr)
	}

	return &ClaimedOutgoingInvite{
		InviteString:      row.InviteString,
		IssuerFQDN:        row.ProviderFQDN,
		PasteTargetOrigin: run.TargetOrigin,
		PasteTargetHost:   run.TargetHost,
		ExpiresAt:         time.Unix(row.ExpiresAt, 0).UTC(),
	}, nil
}
