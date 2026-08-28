// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
)

// indexOriginCreateIndex is the PRAGMA index_list origin of an explicit
// CREATE INDEX statement. Auto-indexes ("u" for inline UNIQUE constraints,
// "pk" for primary keys) are never contract violations: inline UNIQUE
// coverage lives in validatorUniqueColumns and key positions in the table
// shape contract.
const indexOriginCreateIndex = "c"

func checkUniqueColumns(ctx context.Context, conn *sql.Conn) error {
	for table, columns := range validatorUniqueColumns {
		for _, column := range columns {
			unique, err := hasUniqueIndexOn(ctx, conn, table, column)
			if err != nil {
				return err
			}

			if !unique {
				return fmt.Errorf("validatorcore: schema: %s.%s must be UNIQUE", table, column)
			}
		}
	}

	return nil
}

func checkForeignKeyActions(ctx context.Context, conn *sql.Conn) error {
	for table := range validatorTableContract {
		expected := validatorForeignKeys[table]

		fks, err := readForeignKeyShapes(ctx, conn, table)
		if err != nil {
			return err
		}

		byColumn := make(map[string]fkExpectation, len(fks))

		for _, fk := range fks {
			if _, duplicate := byColumn[fk.from]; duplicate {
				return fmt.Errorf(
					"validatorcore: schema: %s.%s has duplicate foreign keys",
					table, fk.from,
				)
			}

			byColumn[fk.from] = fk.fkExpectation
		}

		if len(fks) != len(expected) {
			return fmt.Errorf(
				"validatorcore: schema: %s has %d foreign keys, want %d",
				table, len(fks), len(expected),
			)
		}

		for from, want := range expected {
			got, ok := byColumn[from]
			if !ok {
				return fmt.Errorf("validatorcore: schema: %s.%s FK is missing", table, from)
			}

			if got != want {
				return fmt.Errorf(
					"validatorcore: schema: %s.%s FK = %+v, want %+v",
					table, from, got, want,
				)
			}
		}
	}

	return nil
}

func checkIndexContract(ctx context.Context, conn *sql.Conn) error {
	for _, want := range validatorIndexContract {
		if err := checkIndex(ctx, conn, want); err != nil {
			return err
		}
	}

	return checkNoUnexpectedIndexes(ctx, conn)
}

// checkNoUnexpectedIndexes rejects every explicitly created named index on a
// validator-owned table that is not part of validatorIndexContract. SQLite
// auto-indexes for inline UNIQUE constraints and primary keys are skipped;
// those are covered by validatorUniqueColumns and the table shape contract.
func checkNoUnexpectedIndexes(ctx context.Context, conn *sql.Conn) error {
	expected := make(map[string]bool, len(validatorIndexContract))
	for _, want := range validatorIndexContract {
		expected[want.name] = true
	}

	for table := range validatorTableContract {
		indexes, err := readNamedIndexes(ctx, conn, table)
		if err != nil {
			return err
		}

		for _, index := range indexes {
			if index.origin != indexOriginCreateIndex {
				continue
			}

			if !expected[index.name] {
				return fmt.Errorf(
					"validatorcore: schema: %s carries unexpected index %s",
					table, index.name,
				)
			}
		}
	}

	return nil
}

func checkIndex(ctx context.Context, conn *sql.Conn, want indexContract) error {
	stored, err := readIndexSQL(ctx, conn, want.name)
	if err != nil {
		return err
	}

	if stored == "" {
		return fmt.Errorf("validatorcore: schema: index %s is missing", want.name)
	}

	meta, err := readIndexMeta(ctx, conn, want.table, want.name)
	if err != nil {
		return err
	}

	if meta.unique != want.unique {
		return fmt.Errorf(
			"validatorcore: schema: index %s unique = %v, want %v",
			want.name, meta.unique, want.unique,
		)
	}

	if meta.partial != (want.partial != "") {
		return fmt.Errorf(
			"validatorcore: schema: index %s partial = %v, want %v",
			want.name, meta.partial, want.partial != "",
		)
	}

	columns, err := readIndexColumns(ctx, conn, want.name)
	if err != nil {
		return err
	}

	if !slices.Equal(columns, want.columns) {
		return fmt.Errorf(
			"validatorcore: schema: index %s columns = %v, want %v",
			want.name, columns, want.columns,
		)
	}

	if want.partial != "" {
		if predicate := indexPredicate(stored); predicate != want.partial {
			return fmt.Errorf(
				"validatorcore: schema: index %s predicate = %q, want %q",
				want.name, predicate, want.partial,
			)
		}
	}

	return nil
}

// checkNoUnexpectedTriggers rejects every trigger attached to a
// validator-owned table: the canonical validator schema declares no triggers,
// so any trigger on one of its tables is drift. Triggers on peer tables are
// out of scope and ignored.
func checkNoUnexpectedTriggers(ctx context.Context, conn *sql.Conn) error {
	triggers, err := readTriggerShapes(ctx, conn)
	if err != nil {
		return err
	}

	for _, trigger := range triggers {
		if _, owned := validatorTableContract[trigger.table]; owned {
			return fmt.Errorf(
				"validatorcore: schema: %s carries unexpected trigger %s",
				trigger.table, trigger.name,
			)
		}
	}

	return nil
}
