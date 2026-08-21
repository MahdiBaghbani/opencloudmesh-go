// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"fmt"

	"gorm.io/gorm"
)

// LoadSpecificationRating loads this run's evidence rows in one read
// transaction and folds them with RateSpecification. Report exchanges are
// not loaded; they are transcript-only and do not affect the score.
func (c *Core) LoadSpecificationRating(
	ctx context.Context,
	run *TestRun,
) (SpecificationScore, []SpecificationEvidence, error) {
	if c == nil || c.db == nil {
		return SpecificationScore{}, nil, ErrStoreNotConfigured
	}

	if run == nil {
		return SpecificationScore{}, nil, ErrNilTestRun
	}

	if run.TestRunID == "" {
		return SpecificationScore{}, nil, ErrEmptyTestRunID
	}

	var (
		score    SpecificationScore
		evidence []SpecificationEvidence
	)

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		rows, loadErr := loadSpecificationRatingInputs(tx, run.TestRunID)
		if loadErr != nil {
			return loadErr
		}

		rated, items, rateErr := RateSpecification(run, rows, nil)
		if rateErr != nil {
			return rateErr
		}

		if err := verifyRatingInputsBelongToRun(run.TestRunID, rows); err != nil {
			return err
		}

		score = rated
		evidence = items

		return nil
	})
	if err != nil {
		return SpecificationScore{}, nil, fmt.Errorf("validatorcore: load specification rating: %w", err)
	}

	if evidence == nil {
		evidence = []SpecificationEvidence{}
	}

	return score, evidence, nil
}

func loadSpecificationRatingInputs(
	tx *gorm.DB,
	testRunID string,
) ([]EvidenceRow, error) {
	var rows []EvidenceRow
	if err := tx.
		Where("test_run_id = ?", testRunID).
		Order("created_at ASC, id ASC").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("validatorcore: load evidence rows: %w", err)
	}

	if rows == nil {
		rows = []EvidenceRow{}
	}

	return rows, nil
}

func verifyRatingInputsBelongToRun(testRunID string, rows []EvidenceRow) error {
	for _, row := range rows {
		if row.TestRunID != testRunID {
			return ErrCrossRunRow
		}
	}

	return nil
}
