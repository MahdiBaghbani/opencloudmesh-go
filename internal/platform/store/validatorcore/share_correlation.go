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

// ErrShareCorrelationConflict reports a conflicting canonical correlation
// slot: a different invite ID or token already occupies the run's role slot,
// or more than one row claims it.
var ErrShareCorrelationConflict = errors.New("validatorcore: share correlation conflict")

// ErrShareCorrelationNotFound is returned when a run has no correlation row
// for the requested role and local identity.
var ErrShareCorrelationNotFound = errors.New("validatorcore: share correlation not found")

// GetShareCorrelation returns the run's single correlation row for a role and
// local identity. It is run-scoped, requires a recognized non-empty local
// identity, and returns exactly one row: zero rows is not-found, more than
// one is a conflict, never a silent first.
func (c *Core) GetShareCorrelation(ctx context.Context, testRunID, role, localIdentity string) (*ShareCorrelation, error) {
	if testRunID == "" {
		return nil, errors.New("validatorcore: empty test run id")
	}

	if localIdentity != LocalIdentityA && localIdentity != LocalIdentityB {
		return nil, ErrInvalidLocalIdentity
	}

	var rows []ShareCorrelation

	err := c.db.WithContext(ctx).
		Where("test_run_id = ? AND role = ? AND local_identity = ?", testRunID, role, localIdentity).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("validatorcore: get share correlation: %w", err)
	}

	switch len(rows) {
	case 0:
		return nil, ErrShareCorrelationNotFound
	case 1:
		row := rows[0]

		return &row, nil
	default:
		return nil, ErrShareCorrelationConflict
	}
}

func listShareCorrelationsTx(tx *gorm.DB, testRunID, role string) ([]ShareCorrelation, error) {
	var rows []ShareCorrelation

	err := tx.
		Where("test_run_id = ? AND role = ?", testRunID, role).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("validatorcore: list share correlations: %w", err)
	}

	return rows, nil
}

func stringPtrEqual(s *string, v string) bool {
	return s != nil && *s == v
}
