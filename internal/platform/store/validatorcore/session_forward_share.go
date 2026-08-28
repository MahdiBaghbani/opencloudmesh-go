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
)

// Dispatch reservation lifecycle markers beyond the initial reserved status.
// A reservation status is an outbox marker, never a TestRun state.
const (
	// DispatchStatusClaimed marks a reservation whose single send permit was
	// taken; the outbound POST is owned by exactly one dispatcher.
	DispatchStatusClaimed = "dispatch_claimed"

	// DispatchStatusRemoteSent marks a reservation whose outbound POST
	// succeeded at the receiver. The commit CAS requires this marker and
	// refuses dispatch_reserved, so a commit can never precede the send.
	DispatchStatusRemoteSent = "remote_sent"

	// DispatchStatusCASCommitted marks a reservation whose commit CAS landed:
	// the run advanced to forward_share_sent and the outbox row is complete.
	DispatchStatusCASCommitted = "cas_committed"
)

var (
	errStoreNotConfigured = errors.New("validatorcore: store is not configured")

	// ErrDispatchReservationNotFound is returned when no dispatch reservation
	// row exists for the run.
	ErrDispatchReservationNotFound = errors.New("validatorcore: dispatch reservation not found")

	// ErrDispatchReservationExists is returned when a reserve loses the
	// primary-key race against an existing reservation.
	ErrDispatchReservationExists = errors.New("validatorcore: dispatch reservation already exists")

	// ErrDispatchClaimMiss is returned when the send permit is already taken
	// or the reservation identity does not match the claim.
	ErrDispatchClaimMiss = errors.New("validatorcore: dispatch send already claimed")

	// ErrDispatchNotSent is returned when a commit targets a reservation that
	// has not recorded a successful remote send.
	ErrDispatchNotSent = errors.New("validatorcore: dispatch reservation is not remote_sent")

	// ErrDispatchConjunctMismatch is returned when a reservation does not
	// match the run's designated dispatch identity conjuncts.
	ErrDispatchConjunctMismatch = errors.New("validatorcore: dispatch conjunct mismatch")

	// ErrDispatchClaimLost is returned when an owner-side write presents a
	// claim token that no longer owns the send permit.
	ErrDispatchClaimLost = errors.New("validatorcore: dispatch claim ownership lost")
)

// Column names for the dispatch reservation outbox, so the table-scoped
// writes stay in lockstep with the schema contract.
const (
	colStatus          = "status"
	colWebDAVID        = "webdav_id"
	colSharedSecret    = "shared_secret"
	colReceiverHost    = "receiver_host"
	colShareWith       = "share_with"
	colProbeFilePath   = "probe_file_path"
	colOutgoingShareID = "outgoing_share_id"
	colRemoteSentAt    = "remote_sent_at"
	colCASCommittedAt  = "cas_committed_at"
)

// ForwardDispatchReservation carries the designated dispatch identity
// snapshot for one active run. ShareWith is the normalized user@provider
// compare form; DesignatedShareWith is the raw pin verified in the reserve
// transaction.
type ForwardDispatchReservation struct {
	TestRunID           string
	ProviderID          string
	WebDAVID            string
	SharedSecret        string
	ReceiverHost        string
	ShareWith           string
	DesignatedShareWith string
	ProbeFilePath       string
}

// ForwardShareCommit carries the conjuncts the commit CAS must match:
// provider ID, receiver host, normalized recipient, designated pin,
// snapshotted probe path, and the exact wire URI.
type ForwardShareCommit struct {
	TestRunID           string
	ProviderID          string
	ReceiverHost        string
	ShareWith           string
	DesignatedShareWith string
	ProbeFilePath       string
	WebDAVURI           string
	OutgoingShareID     string
}

// GetDispatchReservation loads the reservation row for a run.
func (c *Core) GetDispatchReservation(ctx context.Context, testRunID string) (*DispatchReservation, error) {
	if c == nil || c.db == nil {
		return nil, errors.New("validatorcore: store is not configured")
	}

	if testRunID == "" {
		return nil, errors.New("validatorcore: empty test run id")
	}

	var row DispatchReservation

	err := c.db.WithContext(ctx).First(&row, "test_run_id = ?", testRunID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrDispatchReservationNotFound
		}

		return nil, fmt.Errorf("validatorcore: get dispatch reservation: %w", err)
	}

	return &row, nil
}

// ReserveForwardDispatch inserts the run's dispatch outbox row in one
// transaction that first proves the run is still the active
// reverse_invite_accepted session pinned to this target and designated
// recipient. The primary key on test_run_id makes concurrent reserves race
// to exactly one winner; the loser gets ErrDispatchReservationExists.
func (c *Core) ReserveForwardDispatch(ctx context.Context, in ForwardDispatchReservation) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if err := validateForwardReservationInput(in); err != nil {
		return err
	}

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return reserveForwardDispatchTx(tx, in, time.Now().Unix())
	})
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return ErrDispatchReservationExists
	}

	return fmt.Errorf("validatorcore: reserve forward dispatch: %w", err)
}

func validateForwardReservationInput(in ForwardDispatchReservation) error {
	if in.TestRunID == "" || in.ProviderID == "" || in.WebDAVID == "" || in.SharedSecret == "" ||
		in.ReceiverHost == "" || in.ShareWith == "" || in.DesignatedShareWith == "" || in.ProbeFilePath == "" {
		return errors.New("validatorcore: forward dispatch reservation requires all identity fields")
	}

	return nil
}

// reserveForwardDispatchTx proves the run still pins this exact designated
// dispatch, then inserts the outbox row.
func reserveForwardDispatchTx(tx *gorm.DB, in ForwardDispatchReservation, now int64) error {
	var run TestRun
	if err := tx.First(&run, "test_run_id = ?", in.TestRunID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrSessionNotFound
		}

		return fmt.Errorf("validatorcore: load test run: %w", err)
	}

	if !run.IsActive || run.State != StateReverseInviteAccepted ||
		run.TargetHost != in.ReceiverHost ||
		!stringPtrEqual(run.DesignatedShareWith, in.DesignatedShareWith) {
		return ErrStateTransitionMiss
	}

	// Table-scoped write: the reservation's UpdatedAt is a nullable unix
	// column, which GORM's name-based auto timestamping cannot fill.
	return tx.Table(tableDispatchReservation).Create(map[string]any{
		colTestRunID:     in.TestRunID,
		colProviderID:    in.ProviderID,
		colWebDAVID:      in.WebDAVID,
		colSharedSecret:  in.SharedSecret,
		colReceiverHost:  in.ReceiverHost,
		colShareWith:     in.ShareWith,
		colProbeFilePath: in.ProbeFilePath,
		colStatus:        DispatchStatusReserved,
		colCreatedAt:     now,
	}).Error
}

// CommitForwardShareSent runs the conjunctive commit CAS in one transaction:
// the reservation must be remote_sent (never dispatch_reserved) and match the
// provider ID, receiver host, normalized recipient, probe path snapshot, and
// the exact snapshotted wire URI, while the run must still be the active
// reverse_invite_accepted session pinned to the same target and designated
// recipient. Only then does the run advance to forward_share_sent and the
// reservation record the commit.
func (c *Core) CommitForwardShareSent(ctx context.Context, in ForwardShareCommit) error {
	if c == nil || c.db == nil {
		return errStoreNotConfigured
	}

	if err := validateForwardCommitInput(in); err != nil {
		return err
	}

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return commitForwardShareSentTx(tx, in, time.Now().Unix())
	})
	if err != nil {
		return fmt.Errorf("validatorcore: commit forward share sent: %w", err)
	}

	return nil
}

func validateForwardCommitInput(in ForwardShareCommit) error {
	if in.TestRunID == "" || in.ProviderID == "" || in.ReceiverHost == "" ||
		in.ShareWith == "" || in.DesignatedShareWith == "" || in.ProbeFilePath == "" || in.WebDAVURI == "" {
		return errors.New("validatorcore: forward share commit requires all identity conjuncts")
	}

	return nil
}

// commitForwardShareSentTx loads the reservation, enforces every identity
// conjunct, then flips the run and stamps the commit atomically.
func commitForwardShareSentTx(tx *gorm.DB, in ForwardShareCommit, now int64) error {
	var reservation DispatchReservation
	if err := tx.First(&reservation, "test_run_id = ?", in.TestRunID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrDispatchReservationNotFound
		}

		return fmt.Errorf("validatorcore: load dispatch reservation: %w", err)
	}

	if reservation.Status != DispatchStatusRemoteSent {
		return ErrDispatchNotSent
	}

	if reservation.ProviderID != in.ProviderID ||
		reservation.ReceiverHost != in.ReceiverHost ||
		reservation.ShareWith != in.ShareWith ||
		reservation.ProbeFilePath != in.ProbeFilePath ||
		reservation.WebDAVID != in.WebDAVURI {
		return ErrDispatchConjunctMismatch
	}

	res := tx.Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = 1 AND state = ? AND target_host = ? AND designated_share_with = ?",
			in.TestRunID, StateReverseInviteAccepted, in.ReceiverHost, in.DesignatedShareWith).
		Updates(map[string]any{
			colState:     StateForwardShareSent,
			colUpdatedAt: now,
		})
	if res.Error != nil {
		return fmt.Errorf("validatorcore: forward share sent CAS: %w", res.Error)
	}

	if res.RowsAffected == 0 {
		return ErrStateTransitionMiss
	}

	return tx.Table(tableDispatchReservation).
		Where("test_run_id = ?", in.TestRunID).
		Updates(map[string]any{
			colStatus:          DispatchStatusCASCommitted,
			colCASCommittedAt:  now,
			colOutgoingShareID: in.OutgoingShareID,
			colUpdatedAt:       now,
		}).Error
}
