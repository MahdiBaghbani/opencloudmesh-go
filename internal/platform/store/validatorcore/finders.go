// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

const findActiveCorrelationSQL = `
		SELECT sc.test_run_id FROM share_correlation sc
		INNER JOIN test_run tr ON tr.test_run_id = sc.test_run_id
		WHERE tr.is_active = 1
		  AND sc.role = ?
		  AND sc.sender_host = ?
		  AND sc.provider_id = ?
		  AND sc.local_identity = ?
		  AND sc.status = 'confirmed'`

const findCorrelationAnyStatusSQL = `
		SELECT sc.test_run_id FROM share_correlation sc
		INNER JOIN test_run tr ON tr.test_run_id = sc.test_run_id
		WHERE tr.is_active = 1
		  AND sc.role = ?
		  AND sc.sender_host = ?
		  AND sc.provider_id = ?
		  AND sc.local_identity = ?`

const findActiveByTargetSQL = `
		SELECT tr.test_run_id FROM test_run tr
		WHERE tr.target_host = ?
		  AND tr.is_active = 1`

const findActiveByProviderIDSQL = `
		SELECT tr.test_run_id FROM test_run tr
		INNER JOIN dispatch_reservation dr ON dr.test_run_id = tr.test_run_id
		WHERE dr.provider_id = ?
		  AND tr.is_active = 1`

const findRunByOutgoingInviteIDSQL = `
		SELECT tr.test_run_id FROM test_run tr
		WHERE tr.outgoing_invite_id = ?
		  AND tr.outgoing_invite_id IS NOT NULL`

// FindActiveCorrelation returns the test_run_id for a confirmed correlation on
// the active session for localIdentity. Pending rows are excluded. Zero or
// multiple matches return gorm.ErrRecordNotFound so callers never receive an
// arbitrary row.
func (c *Core) FindActiveCorrelation(
	ctx context.Context,
	role, senderHost, providerID, localIdentity string,
) (string, error) {
	if err := requireLocalIdentity(localIdentity); err != nil {
		return "", err
	}

	return c.scanExactlyOneTestRunID(
		ctx,
		findActiveCorrelationSQL,
		role,
		senderHost,
		providerID,
		localIdentity,
	)
}

// FindCorrelationAnyStatus returns the test_run_id for an active correlation
// for localIdentity regardless of status. Intended for pending-inclusive
// confirm-hook use only. Zero or multiple matches return gorm.ErrRecordNotFound
// so callers never receive an arbitrary row.
func (c *Core) FindCorrelationAnyStatus(
	ctx context.Context,
	role, senderHost, providerID, localIdentity string,
) (string, error) {
	if err := requireLocalIdentity(localIdentity); err != nil {
		return "", err
	}

	return c.scanExactlyOneTestRunID(
		ctx,
		findCorrelationAnyStatusSQL,
		role,
		senderHost,
		providerID,
		localIdentity,
	)
}

func requireLocalIdentity(localIdentity string) error {
	switch localIdentity {
	case LocalIdentityA, LocalIdentityB:
		return nil
	default:
		return ErrInvalidLocalIdentity
	}
}

func (c *Core) scanExactlyOneTestRunID(
	ctx context.Context,
	query string,
	args ...any,
) (string, error) {
	if c == nil || c.db == nil {
		return "", errors.New("validatorcore: store is not configured")
	}

	ids := []string{}

	res := c.db.WithContext(ctx).Raw(query, args...).Scan(&ids)
	if res.Error != nil {
		return "", res.Error
	}

	// Reject 0 and >1 matches; never return the first of several rows.
	if res.RowsAffected != 1 || len(ids) != 1 {
		return "", gorm.ErrRecordNotFound
	}

	return ids[0], nil
}

// FindActiveByTarget returns the active test_run_id for targetHost. Empty
// targetHost is an error. Zero or multiple matches return
// gorm.ErrRecordNotFound so callers never receive an arbitrary row.
func (c *Core) FindActiveByTarget(ctx context.Context, targetHost string) (string, error) {
	if targetHost == "" {
		return "", errors.New("validatorcore: empty target host")
	}

	return c.scanExactlyOneTestRunID(ctx, findActiveByTargetSQL, targetHost)
}

// ListActive returns every is_active=1 row, oldest updated_at first. No
// matching rows yield an empty slice, not gorm.ErrRecordNotFound.
func (c *Core) ListActive(ctx context.Context) ([]*TestRun, error) {
	if c == nil || c.db == nil {
		return nil, errors.New("validatorcore: store is not configured")
	}

	rows := []*TestRun{}

	err := c.db.WithContext(ctx).
		Where("is_active = 1").
		Order("updated_at ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("validatorcore: list active: %w", err)
	}

	return rows, nil
}

// FindActiveByProviderID returns the active test_run_id bound to providerID
// on dispatch_reservation. Empty providerID is an error. Zero or multiple
// matches return gorm.ErrRecordNotFound so callers never receive an
// arbitrary row.
func (c *Core) FindActiveByProviderID(ctx context.Context, providerID string) (string, error) {
	if providerID == "" {
		return "", errors.New("validatorcore: empty provider id")
	}

	return c.scanExactlyOneTestRunID(ctx, findActiveByProviderIDSQL, providerID)
}

// FindRunByOutgoingInviteID returns the test_run_id for outgoingInviteID.
// Empty outgoingInviteID is an error. There is no is_active filter so a
// late-flip path can still resolve the row. Zero or multiple matches
// return gorm.ErrRecordNotFound so callers never receive an arbitrary row.
func (c *Core) FindRunByOutgoingInviteID(ctx context.Context, outgoingInviteID string) (string, error) {
	if outgoingInviteID == "" {
		return "", errors.New("validatorcore: empty outgoing invite id")
	}

	return c.scanExactlyOneTestRunID(ctx, findRunByOutgoingInviteIDSQL, outgoingInviteID)
}

// FindOldestReadyWaiterForTarget returns the oldest lock-wait row for
// targetHost: opt_in_active=1, is_active=0, state=passive_running,
// passive_ready_at set, and no persisted discovery or TLS fail evidence.
// Empty targetHost is an error. Missing waiters return ErrSessionNotFound.
func (c *Core) FindOldestReadyWaiterForTarget(
	ctx context.Context, targetHost string,
) (*TestRun, error) {
	if c == nil || c.db == nil {
		return nil, errors.New("validatorcore: store is not configured")
	}

	if targetHost == "" {
		return nil, errors.New("validatorcore: empty target host")
	}

	var row TestRun

	err := c.db.WithContext(ctx).
		Where(
			"opt_in_active = 1 AND is_active = 0 AND state = ? AND "+
				"passive_ready_at IS NOT NULL AND target_host = ? AND "+
				notPersistedFailPredicateSQL(),
			StatePassiveRunning,
			targetHost,
			failGatedAreas(),
			failSeverityAliases(),
		).
		Order("passive_ready_at ASC, created_at ASC, test_run_id ASC").
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrSessionNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("validatorcore: find ready waiter for target: %w", err)
	}

	return &row, nil
}
