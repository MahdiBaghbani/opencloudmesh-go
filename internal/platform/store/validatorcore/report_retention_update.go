// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

const (
	colRetentionTier     = "retention_tier"
	colRetentionLockedAt = "retention_locked_at"
	colExpiresAt         = "expires_at"
)

// ReportRetentionWrite is the typed retention mutation for a public report row.
type ReportRetentionWrite struct {
	RetentionTier     *string
	RetentionLockedAt *int64
	ExpiresAt         *int64
	ClearExpiresAt    bool
	UpdatedAt         int64
	// RequireUnlocked makes the UPDATE match only when retention_locked_at
	// is still NULL. PATCH uses this so a concurrent lock cannot lose.
	RequireUnlocked bool
}

// UpdatePublicReportRetention updates a public, unexpired permanent report.
// It returns the number of affected rows. Zero means the row vanished or no
// longer matches the public-row predicate.
func (c *Core) UpdatePublicReportRetention(
	ctx context.Context,
	testRunID string,
	now int64,
	write ReportRetentionWrite,
) (int64, error) {
	if c == nil || c.db == nil {
		return 0, errors.New("validatorcore: store is not configured")
	}

	id := strings.TrimSpace(testRunID)
	if id == "" {
		return 0, errors.New("validatorcore: empty test run id")
	}

	updates := map[string]any{
		colUpdatedAt: write.UpdatedAt,
	}
	if write.RetentionTier != nil {
		updates[colRetentionTier] = *write.RetentionTier
	}

	if write.RetentionLockedAt != nil {
		updates[colRetentionLockedAt] = *write.RetentionLockedAt
	}

	switch {
	case write.ClearExpiresAt:
		updates[colExpiresAt] = gorm.Expr("NULL")
	case write.ExpiresAt != nil:
		updates[colExpiresAt] = *write.ExpiresAt
	}

	query, args := publicReportRetentionWhere(id, now, write.RequireUnlocked)

	res := c.db.WithContext(ctx).Model(&TestRun{}).
		Where(query, args...).
		Updates(updates)
	if res.Error != nil {
		return 0, fmt.Errorf("validatorcore: update public report retention: %w", res.Error)
	}

	return res.RowsAffected, nil
}

// LockPublicReportRetention atomically locks a public unlocked report.
// It sets retention_locked_at and fills a missing retention_tier with the
// default. It does not write expires_at.
func (c *Core) LockPublicReportRetention(
	ctx context.Context,
	testRunID string,
	now int64,
) (int64, error) {
	if c == nil || c.db == nil {
		return 0, errors.New("validatorcore: store is not configured")
	}

	id := strings.TrimSpace(testRunID)
	if id == "" {
		return 0, errors.New("validatorcore: empty test run id")
	}

	query, args := publicReportRetentionWhere(id, now, true)

	res := c.db.WithContext(ctx).Model(&TestRun{}).
		Where(query, args...).
		Updates(map[string]any{
			colRetentionLockedAt: now,
			colRetentionTier:     gorm.Expr("COALESCE("+colRetentionTier+", ?)", DefaultRetentionTier),
			colUpdatedAt:         now,
		})
	if res.Error != nil {
		return 0, fmt.Errorf("validatorcore: lock public report retention: %w", res.Error)
	}

	return res.RowsAffected, nil
}

func publicReportRetentionWhere(testRunID string, now int64, requireUnlocked bool) (string, []any) {
	query := "test_run_id = ? AND opt_in_permanent = 1 AND harvested_at IS NULL " +
		"AND (expires_at IS NULL OR expires_at > ?)"
	args := []any{testRunID, now}

	if requireUnlocked {
		query += " AND retention_locked_at IS NULL"
	}

	return query, args
}
