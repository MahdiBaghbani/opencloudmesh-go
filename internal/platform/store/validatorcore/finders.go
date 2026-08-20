// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"

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

const findOneActiveSQL = `
		SELECT tr.test_run_id FROM test_run tr
		WHERE tr.is_active = 1
		  AND (
		    (? = 'a')
		    OR (? = 'b' AND tr.bob_user_id IS NOT NULL AND tr.bob_user_id != '')
		  )`

// FindOneActive returns the active test_run_id visible to localIdentity.
// Identity a matches the singleton active row. Identity b matches only after
// bob_user_id is set. Zero or multiple matches return gorm.ErrRecordNotFound
// so callers never receive an arbitrary row.
func (c *Core) FindOneActive(
	ctx context.Context, localIdentity string,
) (string, error) {
	if err := requireLocalIdentity(localIdentity); err != nil {
		return "", err
	}

	return c.scanExactlyOneTestRunID(
		ctx,
		findOneActiveSQL,
		localIdentity,
		localIdentity,
	)
}

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
