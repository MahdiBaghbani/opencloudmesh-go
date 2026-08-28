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

	"gorm.io/gorm"
)

// validatorSchemaVersion is the only validator schema version this build
// creates and accepts. Any other recorded version fails closed.
const validatorSchemaVersion = 1

// Validator-owned table names.
const (
	tableTestRun             = "test_run"
	tableShareCorrelation    = "share_correlation"
	tableStatsRaw            = "stats_raw"
	tableStatsAggregate      = "stats_aggregate"
	tableReportExchange      = "report_exchange"
	tableEvidenceRow         = "evidence_row"
	tableDispatchReservation = "dispatch_reservation"
	tableValidatorSchema     = "validator_schema"
)

// ErrUnsupportedValidatorSchemaVersion is returned when the database records a
// validator schema version this build does not understand. The store fails
// closed before any destructive action.
var ErrUnsupportedValidatorSchemaVersion = errors.New("validatorcore: unsupported validator schema version")

// ErrValidatorSchemaShapeMismatch is returned when a recorded version-1
// database does not match this build's schema shape. The store refuses the
// database without dropping validator tables, peer tables, or the SQLite
// file. Recover by deleting the validator_schema row or the validator
// DataDir so the next open can recreate the schema. Never delete ocm.db:
// that file also holds peer tables.
var ErrValidatorSchemaShapeMismatch = errors.New("validatorcore: recorded version-1 schema shape mismatch; delete the validator_schema row or the validator DataDir to recover, never ocm.db")

// legacyValidatorTables are the validator tables dropped during recovery
// before the final schema is created. Recovery is table-scoped and runs
// only when no validator_schema version row exists yet. Children are
// dropped first so leftover FKs cannot block the parent drop. The leftover
// stats_aggregate name is included so a prior-shape database is cleaned
// without remaining after recovery.
var legacyValidatorTables = []string{
	tableEvidenceRow,
	tableReportExchange,
	tableDispatchReservation,
	tableShareCorrelation,
	tableStatsRaw,
	tableStatsAggregate,
	tableTestRun,
	tableValidatorSchema,
}

// ApplyValidatorSchema creates or validates the validator schema on db. It is
// the single validator schema applicator: one explicit DDL sequence inside one
// SQLite transaction opened with BEGIN IMMEDIATE, with the validator_schema
// version row written in the same transaction. No GORM AutoMigrate, no ALTER
// chains, no migration framework.
//
// Version handling fails closed: a recorded version other than the current
// one aborts before any table is dropped. A recorded version-1 database
// whose shape does not match this build is refused without touching
// validator tables or peer tables. Recover by deleting the validator_schema
// row or the validator DataDir; never delete ocm.db. Peer tables are never
// touched.
func ApplyValidatorSchema(db *gorm.DB) error {
	if db == nil {
		return errors.New("validatorcore: nil db")
	}

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("validatorcore: schema: sql handle: %w", err)
	}

	// Pin the pool to a single connection so BEGIN IMMEDIATE and every DDL
	// statement run on the same SQLite connection, then restore pool settings.
	prevMaxOpen := sqlDB.Stats().MaxOpenConnections
	sqlDB.SetMaxOpenConns(1)

	defer sqlDB.SetMaxOpenConns(prevMaxOpen)

	ctx := context.Background()

	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("validatorcore: schema: acquire connection: %w", err)
	}

	//nolint:errcheck // best-effort release; a close failure after commit is not actionable
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("validatorcore: schema: begin immediate: %w", err)
	}

	committed := false

	defer func() {
		if !committed {
			// The caller context may already be done; rollback must still run.
			//nolint:errcheck // best-effort rollback; the original error is already returned
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	if err := applyValidatorSchemaTx(ctx, conn); err != nil {
		return err
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("validatorcore: schema: commit: %w", err)
	}

	committed = true

	return nil
}

func applyValidatorSchemaTx(ctx context.Context, conn *sql.Conn) error {
	version, found, err := readValidatorSchemaVersion(ctx, conn)
	if err != nil {
		return err
	}

	if found {
		if version != validatorSchemaVersion {
			return fmt.Errorf("%w: %d", ErrUnsupportedValidatorSchemaVersion, version)
		}

		if err := validateValidatorSchema(ctx, conn); err != nil {
			return fmt.Errorf("%w: %w", ErrValidatorSchemaShapeMismatch, err)
		}

		return nil
	}

	for _, table := range legacyValidatorTables {
		if _, err := conn.ExecContext(ctx, "DROP TABLE IF EXISTS "+table); err != nil {
			return fmt.Errorf("validatorcore: schema: drop legacy %s: %w", table, err)
		}
	}

	for _, stmt := range validatorSchemaStatements {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("validatorcore: schema: apply statement: %w", err)
		}
	}

	return nil
}

// readValidatorSchemaVersion returns the recorded schema version. found is
// false when the validator_schema table is missing or empty (a fresh
// install, a pre-versioning database, or an operator-deleted version row).
// A table with more than one row fails closed as malformed.
func readValidatorSchemaVersion(ctx context.Context, conn *sql.Conn) (version int, found bool, err error) {
	var tableName string

	row := conn.QueryRowContext(
		ctx,
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'validator_schema'",
	)
	if scanErr := row.Scan(&tableName); scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return 0, false, nil
		}

		return 0, false, fmt.Errorf("validatorcore: schema: probe validator_schema: %w", scanErr)
	}

	rows, err := conn.QueryContext(ctx, "SELECT version FROM "+tableValidatorSchema)
	if err != nil {
		return 0, false, fmt.Errorf("validatorcore: schema: read validator_schema: %w", err)
	}

	//nolint:errcheck // best-effort release; rows.Err() is checked after iteration
	defer rows.Close()

	var versions []int

	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return 0, false, fmt.Errorf("validatorcore: schema: scan validator_schema: %w", err)
		}

		versions = append(versions, v)
	}

	if err := rows.Err(); err != nil {
		return 0, false, fmt.Errorf("validatorcore: schema: iterate validator_schema: %w", err)
	}

	if len(versions) == 0 {
		return 0, false, nil
	}

	if len(versions) != 1 {
		return 0, false, fmt.Errorf("validatorcore: schema: validator_schema holds %d rows, want exactly 1", len(versions))
	}

	return versions[0], true, nil
}

// validatorSchemaStatements is the final validator schema, applied in order
// inside one BEGIN IMMEDIATE transaction after legacy table recovery.
//
// Deletion contract: non-permanent terminal rows are hard-deleted after
// TerminalRetentionDays, children first. Permanent rows are tombstoned
// via harvested_at by the retention sweep and are never hard-deleted.
// Validator-owned child tables (share_correlation, report_exchange,
// evidence_row, dispatch_reservation) declare ON DELETE RESTRICT so an
// accidental test_run DELETE fails instead of silently erasing evidence.
// evidence_row.exchange_id uses ON UPDATE CASCADE ON DELETE SET NULL so
// evidence rows follow an exchange_id change and survive deletion of an
// individual exchange row.
var validatorSchemaStatements = []string{
	`CREATE TABLE test_run (
		test_run_id TEXT PRIMARY KEY,
		is_active INTEGER NOT NULL CHECK (is_active IN (0, 1)),
		state TEXT NOT NULL CHECK (state IN (
			'created',
			'passive_running',
			'passive_complete',
			'active_running',
			'invite_minted',
			'invite_accepted',
			'reverse_awaiting_invite',
			'reverse_invite_accepted',
			'forward_share_sent',
			'capability_exercise',
			'reverse_awaiting_share',
			'terminal_pass',
			'terminal_fail',
			'interrupted'
		)),
		target_origin TEXT NOT NULL,
		target_host TEXT NOT NULL,
		remote_ocm_id TEXT,
		discovery_url TEXT NOT NULL,
		jwks_uri TEXT,
		platform TEXT,
		api_version TEXT,
		terminal_reason TEXT,
		finished_at INTEGER,
		overall_grade TEXT,
		manifest_schema TEXT NOT NULL,
		manifest_json TEXT,
		bob_user_id TEXT,
		outgoing_invite_id TEXT,
		s1_claimed_at INTEGER,
		reverse_invite_token TEXT,
		reverse_invite_imported_at INTEGER,
		designated_share_with TEXT,
		reverse_share_provider_id TEXT,
		passive_ready_at INTEGER,
		stats_written_at INTEGER,
		opt_in_stats INTEGER NOT NULL DEFAULT 0 CHECK (opt_in_stats IN (0, 1)),
		opt_in_permanent INTEGER NOT NULL DEFAULT 0 CHECK (opt_in_permanent IN (0, 1)),
		opt_in_active INTEGER NOT NULL DEFAULT 0 CHECK (opt_in_active IN (0, 1)),
		opt_in_stats_channel TEXT,
		opt_in_stats_at INTEGER,
		opt_in_permanent_channel TEXT,
		opt_in_permanent_at INTEGER,
		opt_in_active_channel TEXT,
		opt_in_active_at INTEGER,
		retention_tier TEXT,
		retention_locked_at INTEGER,
		expires_at INTEGER,
		permanent_report_id TEXT UNIQUE,
		harvested_at INTEGER,
		harvested_session_artifacts_at INTEGER,
		harvest_reason TEXT,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		CHECK (NOT (state = 'passive_complete' AND opt_in_active = 1))
	)`,
	`CREATE UNIQUE INDEX idx_test_run_one_active ON test_run (is_active) WHERE is_active = 1`,
	`CREATE INDEX idx_test_run_state ON test_run (state)`,
	`CREATE INDEX idx_test_run_bob_user_id ON test_run (bob_user_id)`,
	`CREATE INDEX idx_test_run_expires_at ON test_run (expires_at)`,
	`CREATE INDEX idx_test_run_stats_heal ON test_run (stats_written_at) WHERE opt_in_stats = 1 AND stats_written_at IS NULL`,
	`CREATE UNIQUE INDEX idx_test_run_opt_in_active_ready ON test_run (test_run_id) WHERE opt_in_active = 1 AND is_active = 0 AND state = 'passive_running'`,
	`CREATE UNIQUE INDEX idx_test_run_outgoing_invite ON test_run (outgoing_invite_id) WHERE outgoing_invite_id IS NOT NULL`,
	`CREATE TABLE share_correlation (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		test_run_id TEXT NOT NULL REFERENCES test_run (test_run_id) ON UPDATE CASCADE ON DELETE RESTRICT,
		role TEXT NOT NULL,
		sender_host TEXT NOT NULL,
		provider_id TEXT NOT NULL,
		local_identity TEXT NOT NULL,
		share_id TEXT,
		invite_id TEXT,
		status TEXT NOT NULL DEFAULT 'confirmed',
		created_at INTEGER NOT NULL
	)`,
	`CREATE UNIQUE INDEX idx_share_corr_unique
		ON share_correlation (test_run_id, role, sender_host, provider_id, local_identity)`,
	`CREATE UNIQUE INDEX idx_share_corr_incoming_invite_slot
		ON share_correlation (test_run_id) WHERE role = 'incoming_invite'`,
	`CREATE TABLE report_exchange (
		exchange_id INTEGER PRIMARY KEY AUTOINCREMENT,
		test_run_id TEXT NOT NULL REFERENCES test_run (test_run_id) ON UPDATE CASCADE ON DELETE RESTRICT,
		seq INTEGER NOT NULL,
		captured_at INTEGER NOT NULL,
		started_at INTEGER,
		ended_at INTEGER,
		duration_ms INTEGER,
		direction TEXT NOT NULL,
		actor TEXT,
		local_identity TEXT,
		corr_role TEXT,
		leg TEXT,
		endpoint_id TEXT NOT NULL,
		method TEXT NOT NULL,
		url TEXT NOT NULL,
		host TEXT,
		status_code INTEGER,
		http_version TEXT,
		error_text TEXT,
		request_id TEXT,
		req_headers_json TEXT,
		resp_headers_json TEXT,
		sig_raw TEXT,
		sig_key_id TEXT,
		sig_algorithm TEXT,
		sig_scheme TEXT,
		sig_valid INTEGER,
		digest TEXT,
		req_body_redacted TEXT,
		resp_body_redacted TEXT,
		req_body_sha256 TEXT,
		resp_body_sha256 TEXT,
		req_body_bytes INTEGER,
		resp_body_bytes INTEGER,
		req_body_truncated INTEGER NOT NULL DEFAULT 0,
		resp_body_truncated INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL
	)`,
	`CREATE UNIQUE INDEX idx_report_ex_run_seq ON report_exchange (test_run_id, seq)`,
	`CREATE INDEX idx_report_ex_run_captured ON report_exchange (test_run_id, captured_at)`,
	`CREATE INDEX idx_report_ex_run_leg ON report_exchange (test_run_id, leg)`,
	`CREATE INDEX idx_report_ex_run_identity ON report_exchange (test_run_id, local_identity)`,
	`CREATE INDEX idx_report_ex_run_endpoint ON report_exchange (test_run_id, endpoint_id)`,
	`CREATE UNIQUE INDEX idx_report_ex_idem
		ON report_exchange (test_run_id, direction, request_id)
		WHERE request_id IS NOT NULL AND request_id != ''`,
	`CREATE TABLE evidence_row (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		test_run_id TEXT NOT NULL REFERENCES test_run (test_run_id) ON UPDATE CASCADE ON DELETE RESTRICT,
		leg TEXT CHECK (leg IN ('passive', 'forward', 'reverse')),
		area TEXT NOT NULL CHECK (area IN (
			'discovery',
			'tls',
			'jwks',
			'httpsig',
			'sharing',
			'notification',
			'token',
			'capability'
		)),
		step TEXT NOT NULL,
		reason_code TEXT NOT NULL,
		severity TEXT NOT NULL,
		affects_grade INTEGER NOT NULL,
		payload_redacted TEXT,
		exchange_id INTEGER REFERENCES report_exchange (exchange_id) ON UPDATE CASCADE ON DELETE SET NULL,
		created_at INTEGER NOT NULL
	)`,
	`CREATE UNIQUE INDEX idx_evidence_row ON evidence_row (test_run_id, leg, area, step, reason_code)`,
	`CREATE INDEX idx_evidence_row_area ON evidence_row (area)`,
	`CREATE INDEX idx_evidence_row_leg ON evidence_row (leg)`,
	`CREATE TABLE dispatch_reservation (
		test_run_id TEXT PRIMARY KEY REFERENCES test_run (test_run_id) ON UPDATE CASCADE ON DELETE RESTRICT,
		provider_id TEXT NOT NULL UNIQUE,
		webdav_id TEXT NOT NULL UNIQUE,
		shared_secret TEXT NOT NULL,
		receiver_host TEXT NOT NULL,
		share_with TEXT NOT NULL,
		probe_file_path TEXT NOT NULL,
		status TEXT NOT NULL,
		outgoing_share_id TEXT,
		remote_sent_at INTEGER,
		cas_committed_at INTEGER,
		created_at INTEGER NOT NULL,
		updated_at INTEGER
	)`,
	`CREATE TABLE stats_raw (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		k TEXT NOT NULL UNIQUE,
		host_hash TEXT NOT NULL,
		session_kind TEXT NOT NULL,
		reverse_invite_exercised INTEGER NOT NULL,
		platform TEXT NOT NULL,
		api_version TEXT NOT NULL,
		grade_discovery TEXT,
		grade_tls TEXT,
		grade_jwks TEXT,
		grade_httpsig TEXT,
		grade_sharing TEXT,
		grade_notification TEXT,
		grade_token TEXT,
		grade_capability TEXT,
		created_at INTEGER NOT NULL
	)`,
	`CREATE INDEX idx_stats_raw_host_hash ON stats_raw (host_hash)`,
	`CREATE INDEX idx_stats_raw_session_kind ON stats_raw (session_kind)`,
	`CREATE INDEX idx_stats_raw_platform ON stats_raw (platform)`,
	`CREATE INDEX idx_stats_raw_created_at ON stats_raw (created_at)`,
	`CREATE TABLE validator_schema (
		version INTEGER PRIMARY KEY
	)`,
	`INSERT INTO validator_schema (version) VALUES (1)`,
}
