// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	gosqlite "github.com/glebarez/go-sqlite"
)

// sqliteConstraintUnique is SQLite's SQLITE_CONSTRAINT_UNIQUE extended
// result code (19 | (8 << 8)). The is_active=1 flag probe can hit the
// one-active partial unique index when a live active row already exists;
// that is not a CHECK rejection.
const sqliteConstraintUnique = 2067

const (
	flagProbeSavepoint     = "ocm_validator_flag_probe"
	comboProbeSavepoint    = "ocm_validator_combo_probe"
	evidenceProbeSavepoint = "ocm_validator_evidence_probe"
)

// probeFlagInsert varies one 0/1 column at a time. state stays a live value
// that is not passive_complete so the composite CHECK cannot reject a flag
// probe.
const probeFlagInsert = `INSERT INTO test_run (
	test_run_id, is_active, state,
	target_origin, target_host, discovery_url,
	manifest_schema,
	opt_in_stats, opt_in_permanent, opt_in_active,
	created_at, updated_at
) VALUES (?, ?, 'created', 'https://probe.invalid', 'probe.invalid',
	'https://probe.invalid/.well-known/ocm',
	'ocm-validator-manifest/v1',
	?, ?, ?, 0, 0)`

// probeComboInsert varies state and opt_in_active together so the
// passive_complete + opt_in_active=1 CHECK can be exercised.
const probeComboInsert = `INSERT INTO test_run (
	test_run_id, is_active, state,
	target_origin, target_host, discovery_url,
	manifest_schema, opt_in_active, created_at, updated_at
) VALUES (?, 0, ?, 'https://probe.invalid', 'probe.invalid',
	'https://probe.invalid/.well-known/ocm',
	'ocm-validator-manifest/v1', ?, 0, 0)`

const probeEvidenceParentInsert = `INSERT INTO test_run (
	test_run_id, is_active, state,
	target_origin, target_host, discovery_url,
	manifest_schema, created_at, updated_at
) VALUES (?, 0, 'created', 'https://probe.invalid', 'probe.invalid',
	'https://probe.invalid/.well-known/ocm',
	'ocm-validator-manifest/v1', 0, 0)`

const probeEvidenceInsert = `INSERT INTO evidence_row (
	test_run_id, leg, area, step, reason_code, severity, affects_grade, created_at
) VALUES (?, ?, ?, ?, 'probe', 'info', 0, 0)`

// checkNonStateChecks probes every version-1 CHECK other than test_run.state.
// The state CHECK stays in checkTestRunStateCheck and is not relaxed here.
func checkNonStateChecks(ctx context.Context, conn *sql.Conn) error {
	if err := checkTestRunFlagChecks(ctx, conn); err != nil {
		return err
	}

	if err := checkTestRunPassiveCompleteOptIn(ctx, conn); err != nil {
		return err
	}

	if err := checkEvidenceAreaCheck(ctx, conn); err != nil {
		return err
	}

	return checkEvidenceLegCheck(ctx, conn)
}

func checkTestRunFlagChecks(ctx context.Context, conn *sql.Conn) error {
	for _, column := range testRunFlagCheckColumns {
		for _, value := range requiredFlagValues {
			accepted, err := probeFlagAccepted(ctx, conn, column, value)
			if err != nil {
				return err
			}

			if !accepted {
				return fmt.Errorf(
					"validatorcore: schema: test_run %s CHECK rejects required value %d",
					column, value,
				)
			}
		}

		for _, value := range unknownFlagValues {
			accepted, err := probeFlagAccepted(ctx, conn, column, value)
			if err != nil {
				return err
			}

			if accepted {
				return fmt.Errorf(
					"validatorcore: schema: test_run %s CHECK admits unexpected value %d",
					column, value,
				)
			}
		}
	}

	return nil
}

func checkTestRunPassiveCompleteOptIn(ctx context.Context, conn *sql.Conn) error {
	accepted, err := probeComboAccepted(ctx, conn, StatePassiveComplete, 1)
	if err != nil {
		return err
	}

	if accepted {
		return errors.New(
			"validatorcore: schema: test_run CHECK admits passive_complete with opt_in_active = 1",
		)
	}

	accepted, err = probeComboAccepted(ctx, conn, StatePassiveComplete, 0)
	if err != nil {
		return err
	}

	if !accepted {
		return errors.New(
			"validatorcore: schema: test_run CHECK rejects passive_complete with opt_in_active = 0",
		)
	}

	accepted, err = probeComboAccepted(ctx, conn, StateCreated, 1)
	if err != nil {
		return err
	}

	if !accepted {
		return errors.New(
			"validatorcore: schema: test_run CHECK rejects created with opt_in_active = 1",
		)
	}

	return nil
}

func checkEvidenceAreaCheck(ctx context.Context, conn *sql.Conn) error {
	for _, area := range evidenceRowAreas {
		accepted, err := probeEvidenceAccepted(ctx, conn, evidenceRowLegs[0], area)
		if err != nil {
			return err
		}

		if !accepted {
			return fmt.Errorf(
				"validatorcore: schema: evidence_row area CHECK rejects required area %q",
				area,
			)
		}
	}

	for _, area := range unknownEvidenceAreas {
		accepted, err := probeEvidenceAccepted(ctx, conn, evidenceRowLegs[0], area)
		if err != nil {
			return err
		}

		if accepted {
			return fmt.Errorf(
				"validatorcore: schema: evidence_row area CHECK admits unexpected area %q",
				area,
			)
		}
	}

	return nil
}

func checkEvidenceLegCheck(ctx context.Context, conn *sql.Conn) error {
	for _, leg := range evidenceRowLegs {
		accepted, err := probeEvidenceAccepted(ctx, conn, leg, evidenceRowAreas[0])
		if err != nil {
			return err
		}

		if !accepted {
			return fmt.Errorf(
				"validatorcore: schema: evidence_row leg CHECK rejects required leg %q",
				leg,
			)
		}
	}

	for _, leg := range unknownEvidenceLegs {
		accepted, err := probeEvidenceAccepted(ctx, conn, leg, evidenceRowAreas[0])
		if err != nil {
			return err
		}

		if accepted {
			return fmt.Errorf(
				"validatorcore: schema: evidence_row leg CHECK admits unexpected leg %q",
				leg,
			)
		}
	}

	return nil
}

func probeFlagAccepted(ctx context.Context, conn *sql.Conn, column string, value int) (bool, error) {
	isActive, optStats, optPerm, optActive := 0, 0, 0, 0

	switch column {
	case colIsActive:
		isActive = value
	case colOptInStats:
		optStats = value
	case colOptInPermanent:
		optPerm = value
	case colOptInActive:
		optActive = value
	default:
		return false, fmt.Errorf("validatorcore: schema: unknown flag column %q", column)
	}

	return runCheckProbe(ctx, conn, flagProbeSavepoint, "flag probe", func() error {
		if _, err := conn.ExecContext(
			ctx,
			probeFlagInsert,
			nextStateProbeID(),
			isActive,
			optStats,
			optPerm,
			optActive,
		); err != nil {
			return fmt.Errorf("validatorcore: schema: flag probe insert: %w", err)
		}

		return nil
	}, func(insertErr error) bool {
		// A live is_active=1 row makes the one-active unique index fire
		// before a second 1 can persist. That unique failure means the
		// CHECK admitted 1, so the required-value probe still holds.
		return column == colIsActive && value == 1 && isUniqueConstraintRejection(insertErr)
	})
}

func probeComboAccepted(ctx context.Context, conn *sql.Conn, state string, optInActive int) (bool, error) {
	return runCheckProbe(ctx, conn, comboProbeSavepoint, "combo probe", func() error {
		if _, err := conn.ExecContext(
			ctx,
			probeComboInsert,
			nextStateProbeID(),
			state,
			optInActive,
		); err != nil {
			return fmt.Errorf("validatorcore: schema: combo probe insert: %w", err)
		}

		return nil
	}, nil)
}

func probeEvidenceAccepted(ctx context.Context, conn *sql.Conn, leg, area string) (bool, error) {
	parentID := nextStateProbeID()
	step := nextStateProbeID()

	return runCheckProbe(ctx, conn, evidenceProbeSavepoint, "evidence probe", func() error {
		if _, err := conn.ExecContext(ctx, probeEvidenceParentInsert, parentID); err != nil {
			return fmt.Errorf("validatorcore: schema: evidence probe parent insert: %w", err)
		}

		if _, err := conn.ExecContext(
			ctx,
			probeEvidenceInsert,
			parentID,
			leg,
			area,
			step,
		); err != nil {
			return fmt.Errorf("validatorcore: schema: evidence probe insert: %w", err)
		}

		return nil
	}, nil)
}

// runCheckProbe inserts inside a savepoint that always rolls back, then
// classifies the insert with the same typed CHECK-constraint rule as the
// state probe: success is accepted, SQLITE_CONSTRAINT_CHECK is rejected,
// extraAccepted may treat one other driver error as accepted, and
// anything else fails closed as probe infrastructure.
func runCheckProbe(
	ctx context.Context,
	conn *sql.Conn,
	savepoint string,
	label string,
	insert func() error,
	extraAccepted func(error) bool,
) (bool, error) {
	if _, err := conn.ExecContext(ctx, "SAVEPOINT "+savepoint); err != nil {
		return false, fmt.Errorf("validatorcore: schema: %s savepoint: %w", label, err)
	}

	insertErr := insert()

	if _, err := conn.ExecContext(ctx, "ROLLBACK TO "+savepoint); err != nil {
		return false, fmt.Errorf("validatorcore: schema: %s rollback: %w", label, err)
	}

	if _, err := conn.ExecContext(ctx, "RELEASE "+savepoint); err != nil {
		return false, fmt.Errorf("validatorcore: schema: %s release: %w", label, err)
	}

	if insertErr == nil {
		return true, nil
	}

	if isStateCheckRejection(insertErr) {
		return false, nil
	}

	if extraAccepted != nil && extraAccepted(insertErr) {
		return true, nil
	}

	return false, fmt.Errorf("validatorcore: schema: %s failed: %w", label, insertErr)
}

func isUniqueConstraintRejection(insertErr error) bool {
	var sqliteErr *gosqlite.Error
	if !errors.As(insertErr, &sqliteErr) {
		return false
	}

	return sqliteErr.Code() == sqliteConstraintUnique
}
