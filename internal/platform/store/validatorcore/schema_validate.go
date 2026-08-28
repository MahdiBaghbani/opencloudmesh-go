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
	"strings"
)

// SQLite FK action labels reported by PRAGMA foreign_key_list.
// An unspecified action is reported as "NO ACTION".
const (
	fkCascade = "CASCADE"
	fkSetNull = "SET NULL"
)

// validateValidatorSchema confirms a recorded version-1 schema matches the
// final shape exactly: leftover retired validator tables (stats_aggregate)
// are absent; every table's columns (type, nullability, default, key
// position) in order; every CHECK (state, flags, passive-complete, evidence
// area and leg); inline UNIQUE constraints; every named index with columns
// and partial predicate; every foreign key with its referenced table/column
// and actions; and zero triggers on validator-owned tables. It never repairs
// or upgrades: any mismatch fails closed. Peer tables are not inspected.
func validateValidatorSchema(ctx context.Context, conn *sql.Conn) error {
	if err := checkRetiredValidatorTables(ctx, conn); err != nil {
		return err
	}

	for table := range validatorTableContract {
		if err := checkTableShape(ctx, conn, table); err != nil {
			return err
		}
	}

	if err := checkTestRunStateCheck(ctx, conn); err != nil {
		return err
	}

	if err := checkNonStateChecks(ctx, conn); err != nil {
		return err
	}

	if err := checkUniqueColumns(ctx, conn); err != nil {
		return err
	}

	if err := checkForeignKeyActions(ctx, conn); err != nil {
		return err
	}

	if err := checkIndexContract(ctx, conn); err != nil {
		return err
	}

	return checkNoUnexpectedTriggers(ctx, conn)
}

// checkRetiredValidatorTables rejects a leftover stats_aggregate table on a
// recorded version-1 database. The aggregate is a retired validator-owned
// name: its presence is a shape mismatch. The check names that table only
// and does not inventory or mutate peer tables. Unversioned recovery still
// drops the leftover name via legacyValidatorTables before CREATE.
func checkRetiredValidatorTables(ctx context.Context, conn *sql.Conn) error {
	var name string

	row := conn.QueryRowContext(
		ctx,
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
		tableStatsAggregate,
	)
	if err := row.Scan(&name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}

		return fmt.Errorf(
			"validatorcore: schema: probe retired table %s: %w",
			tableStatsAggregate,
			err,
		)
	}

	return fmt.Errorf(
		"validatorcore: schema: version %d but retired table %s is present",
		validatorSchemaVersion,
		tableStatsAggregate,
	)
}

func checkTableShape(ctx context.Context, conn *sql.Conn, table string) error {
	cols, err := readColumnShapes(ctx, conn, table)
	if err != nil {
		return err
	}

	if len(cols) == 0 {
		return fmt.Errorf(
			"validatorcore: schema: version %d but table %s is missing",
			validatorSchemaVersion, table,
		)
	}

	want := validatorTableContract[table]

	if len(cols) != len(want) {
		return fmt.Errorf(
			"validatorcore: schema: version %d but %s has %d columns, want %d",
			validatorSchemaVersion, table, len(cols), len(want),
		)
	}

	for pos, wantCol := range want {
		if cols[pos].name != wantCol.name {
			return fmt.Errorf(
				"validatorcore: schema: version %d but %s column %d is %s, want %s",
				validatorSchemaVersion, table, pos, cols[pos].name, wantCol.name,
			)
		}

		if err := checkColumnShape(table, cols[pos], wantCol); err != nil {
			return err
		}
	}

	return nil
}

func checkColumnShape(table string, got columnShape, want columnContract) error {
	if !strings.EqualFold(got.colType, want.colType) {
		return fmt.Errorf(
			"validatorcore: schema: %s.%s type = %s, want %s",
			table, want.name, got.colType, want.colType,
		)
	}

	if got.notNull != want.notNull {
		return fmt.Errorf(
			"validatorcore: schema: %s.%s NOT NULL = %v, want %v",
			table, want.name, got.notNull, want.notNull,
		)
	}

	gotDflt, wantDflt := columnDefaultText(got.dflt), "NULL"

	if want.dflt != nil {
		wantDflt = *want.dflt
	}

	if gotDflt != wantDflt {
		return fmt.Errorf(
			"validatorcore: schema: %s.%s default = %s, want %s",
			table, want.name, gotDflt, wantDflt,
		)
	}

	if got.pk != want.pk {
		return fmt.Errorf(
			"validatorcore: schema: %s.%s primary key position = %d, want %d",
			table, want.name, got.pk, want.pk,
		)
	}

	return nil
}

func columnDefaultText(dflt sql.NullString) string {
	if !dflt.Valid {
		return "NULL"
	}

	return dflt.String
}
