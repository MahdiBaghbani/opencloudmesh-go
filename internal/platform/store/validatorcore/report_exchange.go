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

// InsertReportExchange persists one captured HTTP exchange for a validator
// session. Seq is allocated as MAX(seq)+1 for the run inside the same GORM
// write transaction as the insert. Concurrent writers serialize on the SQLite
// write lock of that transaction; the (test_run_id, seq) unique index remains
// the last line of defense. A repeated nonempty (test_run_id, direction,
// request_id) is rejected by the partial unique index. A failed insert rolls
// back without consuming a seq, and an auto-allocated row.Seq is cleared so a
// retry can allocate again.
func (c *Core) InsertReportExchange(ctx context.Context, row *ReportExchange) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if err := validateReportExchange(row); err != nil {
		return err
	}

	autoSeq := row.Seq == 0

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return insertReportExchangeDB(tx, row)
	})
	if err != nil {
		if autoSeq {
			row.Seq = 0
		}

		return fmt.Errorf("validatorcore: insert report exchange: %w", err)
	}

	return nil
}

func validateReportExchange(row *ReportExchange) error {
	if row == nil {
		return errors.New("validatorcore: nil report exchange")
	}

	if row.TestRunID == "" {
		return errors.New("validatorcore: empty test_run_id")
	}

	if row.Direction == "" {
		return errors.New("validatorcore: empty direction")
	}

	if row.EndpointID == "" {
		return errors.New("validatorcore: empty endpoint_id")
	}

	if row.Method == "" {
		return errors.New("validatorcore: empty method")
	}

	if row.URL == "" {
		return errors.New("validatorcore: empty url")
	}

	if row.Seq < 0 {
		return errors.New("validatorcore: negative seq")
	}

	return nil
}

func insertReportExchangeDB(tx *gorm.DB, row *ReportExchange) error {
	if row.CreatedAt == 0 {
		row.CreatedAt = time.Now().Unix()
	}

	allocated := false

	if row.Seq == 0 {
		seq, err := nextReportExchangeSeq(tx, row.TestRunID)
		if err != nil {
			return err
		}

		row.Seq = seq
		allocated = true
	}

	if err := tx.Create(row).Error; err != nil {
		if allocated {
			row.Seq = 0
		}

		return NewStoreError(OpInsertReportExchange, err)
	}

	return nil
}

func nextReportExchangeSeq(tx *gorm.DB, testRunID string) (int, error) {
	var maxSeq int

	err := tx.Raw(
		"SELECT COALESCE(MAX(seq), 0) FROM report_exchange WHERE test_run_id = ?",
		testRunID,
	).Scan(&maxSeq).Error
	if err != nil {
		return 0, fmt.Errorf("validatorcore: allocate report exchange seq: %w", err)
	}

	return maxSeq + 1, nil
}
