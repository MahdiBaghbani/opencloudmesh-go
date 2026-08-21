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
)

// ClaimForwardDispatchSend takes the single send permit for a reserved
// dispatch, flipping dispatch_reserved -> dispatch_claimed exactly once so
// concurrent dispatchers race to one sender. The claim token is the owner
// fence: it is recorded in the reservation's outgoing_share_id slot (empty
// until the remote-sent stamp replaces it with the local share row ID) and
// every owner-side write must present it.
func (c *Core) ClaimForwardDispatchSend(ctx context.Context, testRunID, providerID, claimToken string) error {
	if c == nil || c.db == nil {
		return errStoreNotConfigured
	}

	if testRunID == "" || providerID == "" || claimToken == "" {
		return errors.New("validatorcore: dispatch claim requires run id, provider id, and claim token")
	}

	now := time.Now().Unix()

	res := c.db.WithContext(ctx).Table(tableDispatchReservation).
		Where("test_run_id = ? AND provider_id = ? AND status = ?", testRunID, providerID, DispatchStatusReserved).
		Updates(map[string]any{
			colStatus:          DispatchStatusClaimed,
			colOutgoingShareID: claimToken,
			colUpdatedAt:       now,
		})
	if res.Error != nil {
		return fmt.Errorf("validatorcore: claim dispatch send: %w", res.Error)
	}

	if res.RowsAffected == 0 {
		return ErrDispatchClaimMiss
	}

	return nil
}

// MarkForwardDispatchRemoteSent stamps the reservation after the outbound
// POST succeeded. Only the current permit owner can stamp: the claimed row
// must still carry the caller's claim token, which the stamp replaces with
// the local share row ID. A stale owner whose claim was reclaimed fails
// closed with ErrDispatchClaimLost; a repeat stamp with the same provider ID
// after the stamp or commit is idempotent.
func (c *Core) MarkForwardDispatchRemoteSent(ctx context.Context, testRunID, providerID, claimToken, outgoingShareID string) error {
	if c == nil || c.db == nil {
		return errStoreNotConfigured
	}

	if testRunID == "" || providerID == "" || claimToken == "" {
		return errors.New("validatorcore: remote sent stamp requires run id, provider id, and claim token")
	}

	now := time.Now().Unix()

	res := c.db.WithContext(ctx).Table(tableDispatchReservation).
		Where("test_run_id = ? AND provider_id = ? AND status = ? AND outgoing_share_id = ?",
			testRunID, providerID, DispatchStatusClaimed, claimToken).
		Updates(map[string]any{
			colStatus:          DispatchStatusRemoteSent,
			colRemoteSentAt:    now,
			colOutgoingShareID: outgoingShareID,
			colUpdatedAt:       now,
		})
	if res.Error != nil {
		return fmt.Errorf("validatorcore: mark dispatch remote sent: %w", res.Error)
	}

	if res.RowsAffected > 0 {
		return nil
	}

	row, err := c.GetDispatchReservation(ctx, testRunID)
	if err != nil {
		return err
	}

	// A repeat stamp with the same provider ID is idempotent, including after
	// the commit CAS already completed the outbox row.
	if row.ProviderID == providerID &&
		(row.Status == DispatchStatusRemoteSent || row.Status == DispatchStatusCASCommitted) {
		return nil
	}

	if row.ProviderID == providerID && row.Status == DispatchStatusClaimed {
		// Still claimed but under a different token: this caller's permit was
		// reclaimed by a later dispatcher.
		return ErrDispatchClaimLost
	}

	return ErrDispatchConjunctMismatch
}

// ReleaseForwardDispatchClaim returns a claimed send permit to reserved so a
// failed or aborted send can be retried with the same provider identity. Only
// the current permit owner can release; a fenced stale owner fails closed
// with ErrDispatchClaimLost, and a reservation that already recorded the
// remote send is left for the replay path.
func (c *Core) ReleaseForwardDispatchClaim(ctx context.Context, testRunID, providerID, claimToken string) error {
	if c == nil || c.db == nil {
		return errStoreNotConfigured
	}

	if testRunID == "" || providerID == "" || claimToken == "" {
		return errors.New("validatorcore: claim release requires run id, provider id, and claim token")
	}

	res := c.db.WithContext(ctx).Table(tableDispatchReservation).
		Where("test_run_id = ? AND provider_id = ? AND status = ? AND outgoing_share_id = ?",
			testRunID, providerID, DispatchStatusClaimed, claimToken).
		Updates(map[string]any{
			colStatus:          DispatchStatusReserved,
			colOutgoingShareID: nil,
			colUpdatedAt:       time.Now().Unix(),
		})
	if res.Error != nil {
		return fmt.Errorf("validatorcore: release dispatch claim: %w", res.Error)
	}

	if res.RowsAffected > 0 {
		return nil
	}

	row, err := c.GetDispatchReservation(ctx, testRunID)
	if err != nil {
		return err
	}

	if row.ProviderID != providerID {
		return ErrDispatchConjunctMismatch
	}

	if row.Status == DispatchStatusClaimed {
		// Still claimed under a different token: this caller's permit was
		// reclaimed by a later dispatcher.
		return ErrDispatchClaimLost
	}

	// Already reserved (idempotent retry of the release) or already sent: both
	// leave the outbox in a state the dispatch flow can reconcile.
	return nil
}

// ReclaimForwardDispatchClaim retakes a send permit whose owner stopped
// making progress (crash, or a canceled request whose release never ran). The
// compare-and-swap only succeeds when the claimed row still carries the exact
// claim token the caller observed and its last update is older than the
// staleness bound, so a live send keeps its permit, a reservation that
// changed hands since the observation is left alone, and concurrent
// reclaimers race to one winner. The status stays claimed, but the claim
// token rotates: the fenced old owner can no longer stamp, snapshot, or
// release the permit.
func (c *Core) ReclaimForwardDispatchClaim(ctx context.Context, testRunID, providerID, oldToken, newToken string, staleBefore int64) error {
	if c == nil || c.db == nil {
		return errStoreNotConfigured
	}

	if testRunID == "" || providerID == "" || oldToken == "" || newToken == "" {
		return errors.New("validatorcore: claim reclaim requires run id, provider id, and both claim tokens")
	}

	res := c.db.WithContext(ctx).Table(tableDispatchReservation).
		Where("test_run_id = ? AND provider_id = ? AND status = ? AND outgoing_share_id = ? AND updated_at < ?",
			testRunID, providerID, DispatchStatusClaimed, oldToken, staleBefore).
		Updates(map[string]any{
			colOutgoingShareID: newToken,
			colUpdatedAt:       time.Now().Unix(),
		})
	if res.Error != nil {
		return fmt.Errorf("validatorcore: reclaim dispatch claim: %w", res.Error)
	}

	if res.RowsAffected == 0 {
		return ErrDispatchClaimMiss
	}

	return nil
}

// CheckForwardDispatchClaim verifies the caller still owns the send permit
// immediately before the outbound POST: the reservation must still be claimed
// under the caller's claim token. A fenced stale plan fails closed with
// ErrDispatchClaimLost, so it never reaches the receiver.
func (c *Core) CheckForwardDispatchClaim(ctx context.Context, testRunID, providerID, claimToken string) error {
	if c == nil || c.db == nil {
		return errStoreNotConfigured
	}

	if testRunID == "" || providerID == "" || claimToken == "" {
		return errors.New("validatorcore: claim check requires run id, provider id, and claim token")
	}

	row, err := c.GetDispatchReservation(ctx, testRunID)
	if err != nil {
		return err
	}

	if row.ProviderID != providerID {
		return ErrDispatchConjunctMismatch
	}

	if row.Status != DispatchStatusClaimed || row.OutgoingShareID == nil || *row.OutgoingShareID != claimToken {
		return ErrDispatchClaimLost
	}

	return nil
}

// SnapshotForwardDispatchWireURI records the exact WebDAV URI the dispatch
// puts on the wire. webdav_id starts as the bare minted ID; once the handler
// resolves the receiver's URI kind, the exact wire form replaces it (a
// relative-form receiver makes the write a no-op). The snapshot is an
// owner-side write inside the send window: the reservation must be claimed
// under the caller's current claim token, so a fenced stale owner can never
// overwrite the winner's wire identity.
func (c *Core) SnapshotForwardDispatchWireURI(ctx context.Context, testRunID, providerID, claimToken, uri string) error {
	if c == nil || c.db == nil {
		return errStoreNotConfigured
	}

	if testRunID == "" || providerID == "" || claimToken == "" || uri == "" {
		return errors.New("validatorcore: wire uri snapshot requires run id, provider id, claim token, and uri")
	}

	res := c.db.WithContext(ctx).Table(tableDispatchReservation).
		Where("test_run_id = ? AND provider_id = ? AND status = ? AND outgoing_share_id = ?",
			testRunID, providerID, DispatchStatusClaimed, claimToken).
		Updates(map[string]any{
			colWebDAVID:  uri,
			colUpdatedAt: time.Now().Unix(),
		})
	if res.Error != nil {
		return fmt.Errorf("validatorcore: snapshot dispatch wire uri: %w", res.Error)
	}

	if res.RowsAffected > 0 {
		return nil
	}

	row, err := c.GetDispatchReservation(ctx, testRunID)
	if err != nil {
		return err
	}

	if row.ProviderID != providerID {
		return ErrDispatchConjunctMismatch
	}

	if row.Status == DispatchStatusClaimed {
		// Claimed under a different token: this caller's permit was reclaimed.
		// Fail closed even when the URI value already matches.
		return ErrDispatchClaimLost
	}

	if row.WebDAVID == uri {
		// Idempotent repeat once the send window closed with the same value.
		return nil
	}

	return ErrDispatchConjunctMismatch
}
