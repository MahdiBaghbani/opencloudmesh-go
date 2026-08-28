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

// findRunByRecipientAndTargetSQL resolves one run by the local recipient of
// an inbound share and the normalized sender host. bob_user_id is minted per
// run when the active lock is taken, so the pair matches at most one row; it
// is also the only recipient binding the schema carries, which keeps the
// lookup Bob-only by construction. There is no is_active filter: the
// late-flip path runs after the row was interrupted, so the finder must stay
// usable on inactive rows.
const findRunByRecipientAndTargetSQL = `
	SELECT tr.test_run_id FROM test_run tr
	WHERE tr.target_host = ?
	  AND tr.bob_user_id = ?`

// FindRunByRecipientAndTarget returns the test_run_id of the run whose Bob
// binding matches the recipient. targetHost must be the normalized sender
// authority. Zero or multiple matches return gorm.ErrRecordNotFound so
// callers never receive an arbitrary row.
func (c *Core) FindRunByRecipientAndTarget(
	ctx context.Context,
	recipientUserID, targetHost string,
) (string, error) {
	if c == nil || c.db == nil {
		return "", errors.New("validatorcore: store is not configured")
	}

	if recipientUserID == "" || targetHost == "" {
		return "", gorm.ErrRecordNotFound
	}

	type match struct {
		TestRunID string `gorm:"column:test_run_id"`
	}

	rows := []match{}

	res := c.db.WithContext(ctx).Raw(
		findRunByRecipientAndTargetSQL,
		targetHost,
		recipientUserID,
	).Scan(&rows)
	if res.Error != nil {
		return "", res.Error
	}

	if res.RowsAffected != 1 || len(rows) != 1 {
		return "", gorm.ErrRecordNotFound
	}

	return rows[0].TestRunID, nil
}
