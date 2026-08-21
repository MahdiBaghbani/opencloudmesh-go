// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// ocmgo:file-length-ignore: version-1 schema shape validator with table, CHECK, FK, and index probes

package validatorcore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"

	gosqlite "github.com/glebarez/go-sqlite"
)

// SQLite FK action labels reported by PRAGMA foreign_key_list.
// An unspecified action is reported as "NO ACTION".
const (
	fkCascade = "CASCADE"
	fkSetNull = "SET NULL"
)

// indexOriginCreateIndex is the PRAGMA index_list origin of an explicit
// CREATE INDEX statement. Auto-indexes ("u" for inline UNIQUE constraints,
// "pk" for primary keys) are never contract violations: inline UNIQUE
// coverage lives in validatorUniqueColumns and key positions in the table
// shape contract.
const indexOriginCreateIndex = "c"

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

// stateProbeSavepoint wraps every state CHECK probe insert so the row is always rolled back and never persists.
const stateProbeSavepoint = "ocm_validator_state_probe"

// stateProbeCounter yields a fresh, unique sentinel primary key per probe
// insert, eliminating primary-key collisions as a class so the only insert
// failures left to classify are the state CHECK and unrelated errors.
var stateProbeCounter atomic.Uint64

// nextStateProbeID returns a probe-unique sentinel test_run primary key; every probe insert rolls back, so the row never persists and the id is never reused.
func nextStateProbeID() string {
	return fmt.Sprintf("__ocm_validator_state_probe_%d__", stateProbeCounter.Add(1))
}

// probeStateInsert inserts one test_run row whose only variable columns are the
// primary key and state; every other NOT NULL column gets a valid literal.
// checkTableShape has already confirmed the exact contract columns, so under a
// well-formed schema the state CHECK is the constraint this row exercises.
const probeStateInsert = `INSERT INTO test_run (
	test_run_id, is_active, state,
	target_origin, target_host, discovery_url,
	manifest_schema, created_at, updated_at
) VALUES (?, 0, ?, 'https://probe.invalid', 'probe.invalid',
	'https://probe.invalid/.well-known/ocm',
	'ocm-validator-manifest/v1', 0, 0)`

// unknownStateProbes are literals the live state CHECK must reject. They stand
// in for an over-broad constraint (a tautology tail, a typo, an empty value,
// or a retired live name): if any is admitted, the constraint is wider than
// the live state set.
var unknownStateProbes = []string{
	"",
	"RUNNING",
	"terminal_unknown",
	"zzz_not_a_state",
	"reverse_invite_solicited",
	"reverse_invite_imported",
}

// checkTestRunStateCheck verifies the enforced test_run.state CHECK by probing
// the live constraint instead of parsing stored DDL text: inside a savepoint
// that always rolls back, every live state must be accepted and every dormant
// or unexpected literal rejected. Because the probe tests what SQLite enforces,
// a broadened CHECK cannot change the result, so there is no SQL text to spoof.
func checkTestRunStateCheck(ctx context.Context, conn *sql.Conn) error {
	for _, state := range testRunStates {
		accepted, err := probeStateAccepted(ctx, conn, state)
		if err != nil {
			return err
		}

		if !accepted {
			return fmt.Errorf("validatorcore: schema: test_run state CHECK rejects required state %q", state)
		}
	}

	for _, state := range unknownStateProbes {
		if err := requireStateRejected(ctx, conn, state, "admits unexpected state"); err != nil {
			return err
		}
	}

	for _, state := range dormantTestRunStates {
		if err := requireStateRejected(ctx, conn, state, "admits dormant state"); err != nil {
			return err
		}
	}

	return checkTestRunStateCollation(ctx, conn)
}

// checkTestRunStateCollation proves the state CHECK matches state names under
// the SQLite default BINARY collation: a case variant and a trailing-space
// variant of a live state must both be rejected, since a NOCASE or RTRIM column
// would admit one and weaken the exact matching the CHECK and state index need.
func checkTestRunStateCollation(ctx context.Context, conn *sql.Conn) error {
	if len(testRunStates) == 0 {
		return nil
	}

	live := testRunStates[0]

	if caseVariant := strings.ToUpper(live); caseVariant != live {
		accepted, err := probeStateAccepted(ctx, conn, caseVariant)
		if err != nil {
			return err
		}

		if accepted {
			return fmt.Errorf(
				"validatorcore: schema: test_run.state matches case-insensitively (admits %q), want case-sensitive %s",
				caseVariant, testRunStateCollation,
			)
		}
	}

	spaceVariant := live + " "

	accepted, err := probeStateAccepted(ctx, conn, spaceVariant)
	if err != nil {
		return err
	}

	if accepted {
		return fmt.Errorf(
			"validatorcore: schema: test_run.state ignores trailing spaces (admits %q), want exact %s matching",
			spaceVariant, testRunStateCollation,
		)
	}

	return nil
}

// requireStateRejected fails closed when the live state CHECK admits state.
// admitted describes how the constraint is too broad for the error message.
func requireStateRejected(ctx context.Context, conn *sql.Conn, state, admitted string) error {
	accepted, err := probeStateAccepted(ctx, conn, state)
	if err != nil {
		return err
	}

	if accepted {
		return fmt.Errorf("validatorcore: schema: test_run state CHECK %s %q", admitted, state)
	}

	return nil
}

// sqliteConstraintCheck is SQLite's SQLITE_CONSTRAINT_CHECK extended result
// code, reported when an insert violates a CHECK constraint. The glebarez
// driver enables extended result codes, so a genuine CHECK rejection surfaces
// this exact code rather than the generic SQLITE_CONSTRAINT (19).
const sqliteConstraintCheck = 275

// isStateCheckRejection reports whether insertErr is a SQLite CHECK-constraint
// failure. State and non-state CHECK probes share this classifier: it is the
// only insert error meaning a CHECK refused the value. It relies solely on
// the driver's typed extended result code: any other error (PK, NOT NULL,
// UNIQUE, FK, trigger, infra, or a non-driver error whose text merely
// mentions a CHECK) is not a rejection and fails closed as a probe error.
func isStateCheckRejection(insertErr error) bool {
	var sqliteErr *gosqlite.Error
	if !errors.As(insertErr, &sqliteErr) {
		return false
	}

	return sqliteErr.Code() == sqliteConstraintCheck
}

// probeStateAccepted inserts a probe row (fresh unique primary key) inside a
// savepoint that always rolls back, then classifies the insert: no error is
// accepted (true); a CHECK-constraint failure is rejected (false); any other
// error is returned as a probe-infrastructure failure so validation fails closed.
func probeStateAccepted(ctx context.Context, conn *sql.Conn, state string) (bool, error) {
	if _, err := conn.ExecContext(ctx, "SAVEPOINT "+stateProbeSavepoint); err != nil {
		return false, fmt.Errorf("validatorcore: schema: state probe savepoint: %w", err)
	}

	_, insertErr := conn.ExecContext(ctx, probeStateInsert, nextStateProbeID(), state)

	if _, err := conn.ExecContext(ctx, "ROLLBACK TO "+stateProbeSavepoint); err != nil {
		return false, fmt.Errorf("validatorcore: schema: state probe rollback: %w", err)
	}

	if _, err := conn.ExecContext(ctx, "RELEASE "+stateProbeSavepoint); err != nil {
		return false, fmt.Errorf("validatorcore: schema: state probe release: %w", err)
	}

	if insertErr == nil {
		return true, nil
	}

	if isStateCheckRejection(insertErr) {
		return false, nil
	}

	return false, fmt.Errorf("validatorcore: schema: state probe failed: %w", insertErr)
}

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
