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

// TouchUpdatedAt refreshes updated_at on a live active run so the stall
// sweep sees recent progress. It does not change state. A miss (missing,
// inactive, or already terminal) is a successful no-op.
func (c *Core) TouchUpdatedAt(ctx context.Context, testRunID string) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if testRunID == "" {
		return errors.New("validatorcore: empty test run id")
	}

	now := time.Now().Unix()

	res := c.db.WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ? AND is_active = 1 AND state NOT IN ?", testRunID, terminalStateSet()).
		Updates(map[string]any{
			colUpdatedAt: now,
		})
	if res.Error != nil {
		return fmt.Errorf("validatorcore: touch updated_at: %w", res.Error)
	}

	return nil
}
