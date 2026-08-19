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

// SQLite schema introspection helpers for version-1 validation. Each reader
// reports the live database shape exactly as PRAGMA or sqlite_master exposes
// it; schema_validate.go compares the readings against schema_contract.go.

type columnShape struct {
	name    string
	colType string
	notNull bool
	dflt    sql.NullString
	pk      int
}

// readColumnShapes returns the columns of table in declaration (cid) order.
func readColumnShapes(ctx context.Context, conn *sql.Conn, table string) ([]columnShape, error) {
	rows, err := conn.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return nil, fmt.Errorf("validatorcore: schema: table info %s: %w", table, err)
	}

	//nolint:errcheck // best-effort release; rows.Err() is checked after iteration
	defer rows.Close()

	var cols []columnShape

	for rows.Next() {
		var (
			cid   int
			shape columnShape
		)

		if err := rows.Scan(&cid, &shape.name, &shape.colType, &shape.notNull, &shape.dflt, &shape.pk); err != nil {
			return nil, fmt.Errorf("validatorcore: schema: scan table info %s: %w", table, err)
		}

		cols = append(cols, shape)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("validatorcore: schema: iterate table info %s: %w", table, err)
	}

	return cols, nil
}

// readIndexSQL returns the stored CREATE INDEX text for name, or "" when no
// index with that name exists.
func readIndexSQL(ctx context.Context, conn *sql.Conn, name string) (string, error) {
	var sqlText string

	row := conn.QueryRowContext(
		ctx,
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?",
		name,
	)
	if err := row.Scan(&sqlText); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}

		return "", fmt.Errorf("validatorcore: schema: read index %s: %w", name, err)
	}

	return sqlText, nil
}

type indexMeta struct {
	unique  bool
	partial bool
}

func readIndexMeta(ctx context.Context, conn *sql.Conn, table, name string) (indexMeta, error) {
	rows, err := conn.QueryContext(ctx, "PRAGMA index_list("+table+")")
	if err != nil {
		return indexMeta{}, fmt.Errorf("validatorcore: schema: index list %s: %w", table, err)
	}

	//nolint:errcheck // best-effort release; rows.Err() is checked after iteration
	defer rows.Close()

	var (
		meta  indexMeta
		found bool
	)

	for rows.Next() {
		var (
			seq       int
			indexName string
			unique    int
			origin    string
			partial   int
		)

		if err := rows.Scan(&seq, &indexName, &unique, &origin, &partial); err != nil {
			return indexMeta{}, fmt.Errorf("validatorcore: schema: scan index list %s: %w", table, err)
		}

		if indexName == name {
			meta = indexMeta{unique: unique == 1, partial: partial == 1}
			found = true
		}
	}

	if err := rows.Err(); err != nil {
		return indexMeta{}, fmt.Errorf("validatorcore: schema: iterate index list %s: %w", table, err)
	}

	if !found {
		return indexMeta{}, fmt.Errorf("validatorcore: schema: index %s missing on %s", name, table)
	}

	return meta, nil
}

// readIndexColumns returns the indexed columns of index in key order.
func readIndexColumns(ctx context.Context, conn *sql.Conn, index string) ([]string, error) {
	rows, err := conn.QueryContext(ctx, "PRAGMA index_info("+index+")")
	if err != nil {
		return nil, fmt.Errorf("validatorcore: schema: index info %s: %w", index, err)
	}

	//nolint:errcheck // best-effort release; rows.Err() is checked after iteration
	defer rows.Close()

	var columns []string

	for rows.Next() {
		var (
			seqno int
			cid   int
			name  string
		)

		if err := rows.Scan(&seqno, &cid, &name); err != nil {
			return nil, fmt.Errorf("validatorcore: schema: scan index info %s: %w", index, err)
		}

		columns = append(columns, name)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("validatorcore: schema: iterate index info %s: %w", index, err)
	}

	return columns, nil
}

// indexPredicate extracts the normalized WHERE predicate from a stored partial
// CREATE INDEX statement, or "" when the index is not partial. The stored text
// keeps the original line breaks, so normalize first, then cut on the keyword.
func indexPredicate(indexSQL string) string {
	const whereClause = " WHERE "

	normalized := normalizeSQL(indexSQL)

	idx := strings.Index(strings.ToUpper(normalized), whereClause)
	if idx < 0 {
		return ""
	}

	return normalized[idx+len(whereClause):]
}

type namedIndex struct {
	name   string
	origin string
}

// readNamedIndexes returns every index on table with its SQLite origin: "c"
// for an explicit CREATE INDEX, "u" for an inline UNIQUE auto-index, and "pk"
// for a PRIMARY KEY auto-index.
func readNamedIndexes(ctx context.Context, conn *sql.Conn, table string) ([]namedIndex, error) {
	rows, err := conn.QueryContext(ctx, "PRAGMA index_list("+table+")")
	if err != nil {
		return nil, fmt.Errorf("validatorcore: schema: index list %s: %w", table, err)
	}

	//nolint:errcheck // best-effort release; rows.Err() is checked after iteration
	defer rows.Close()

	var indexes []namedIndex

	for rows.Next() {
		var (
			seq     int
			index   namedIndex
			unique  int
			partial int
		)

		if err := rows.Scan(&seq, &index.name, &unique, &index.origin, &partial); err != nil {
			return nil, fmt.Errorf("validatorcore: schema: scan index list %s: %w", table, err)
		}

		indexes = append(indexes, index)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("validatorcore: schema: iterate index list %s: %w", table, err)
	}

	return indexes, nil
}

func normalizeSQL(sqlText string) string {
	return strings.Join(strings.Fields(sqlText), " ")
}

func hasUniqueIndexOn(ctx context.Context, conn *sql.Conn, table, column string) (bool, error) {
	rows, err := conn.QueryContext(ctx, "PRAGMA index_list("+table+")")
	if err != nil {
		return false, fmt.Errorf("validatorcore: schema: index list %s: %w", table, err)
	}

	//nolint:errcheck // best-effort release; rows.Err() is checked after iteration
	defer rows.Close()

	var uniqueIndexes []string

	for rows.Next() {
		var (
			seq     int
			name    string
			unique  int
			origin  string
			partial int
		)

		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			return false, fmt.Errorf("validatorcore: schema: scan index list %s: %w", table, err)
		}

		if unique == 1 {
			uniqueIndexes = append(uniqueIndexes, name)
		}
	}

	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("validatorcore: schema: iterate index list %s: %w", table, err)
	}

	for _, index := range uniqueIndexes {
		columns, err := readIndexColumns(ctx, conn, index)
		if err != nil {
			return false, err
		}

		if len(columns) == 1 && columns[0] == column {
			return true, nil
		}
	}

	return false, nil
}

// fkShape is one row of PRAGMA foreign_key_list: the source column plus the
// referenced table/column and actions. Rows are kept as a slice so duplicate
// FK declarations on the same source column survive for validation instead of
// collapsing into a map entry.
type fkShape struct {
	fkExpectation

	from string
}

func readForeignKeyShapes(
	ctx context.Context,
	conn *sql.Conn,
	table string,
) ([]fkShape, error) {
	rows, err := conn.QueryContext(ctx, "PRAGMA foreign_key_list("+table+")")
	if err != nil {
		return nil, fmt.Errorf("validatorcore: schema: fk list %s: %w", table, err)
	}

	//nolint:errcheck // best-effort release; rows.Err() is checked after iteration
	defer rows.Close()

	var fks []fkShape

	for rows.Next() {
		var (
			id, seq         int
			refTable, match string
			shape           fkShape
			to              string
		)

		if err := rows.Scan(&id, &seq, &refTable, &shape.from, &to, &shape.onUpdate, &shape.onDelete, &match); err != nil {
			return nil, fmt.Errorf("validatorcore: schema: scan fk list %s: %w", table, err)
		}

		shape.referencedTable = refTable
		shape.referencedColumn = to
		fks = append(fks, shape)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("validatorcore: schema: iterate fk list %s: %w", table, err)
	}

	return fks, nil
}

// triggerShape is one trigger row from sqlite_master: the trigger name and
// the table it fires on.
type triggerShape struct {
	name  string
	table string
}

// readTriggerShapes returns every trigger recorded in sqlite_master with the
// table it is attached to. The canonical validator schema declares no
// triggers, so any trigger on a validator-owned table is drift.
func readTriggerShapes(ctx context.Context, conn *sql.Conn) ([]triggerShape, error) {
	rows, err := conn.QueryContext(ctx, "SELECT name, tbl_name FROM sqlite_master WHERE type = 'trigger'")
	if err != nil {
		return nil, fmt.Errorf("validatorcore: schema: trigger list: %w", err)
	}

	//nolint:errcheck // best-effort release; rows.Err() is checked after iteration
	defer rows.Close()

	var triggers []triggerShape

	for rows.Next() {
		var trigger triggerShape

		if err := rows.Scan(&trigger.name, &trigger.table); err != nil {
			return nil, fmt.Errorf("validatorcore: schema: scan trigger list: %w", err)
		}

		triggers = append(triggers, trigger)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("validatorcore: schema: iterate trigger list: %w", err)
	}

	return triggers, nil
}
