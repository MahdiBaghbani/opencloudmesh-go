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

// legacyValidatorTables are the pre-versioning validator tables dropped during
// recovery before the final schema is created. Recovery is table-scoped: only
// these four tables may be dropped, and only when no validator_schema version
// row exists yet.
var legacyValidatorTables = []string{
	tableShareCorrelation,
	tableStatsRaw,
	tableStatsAggregate,
	tableTestRun,
}

// ApplyValidatorSchema creates or validates the validator schema on db. It is
// the single validator schema applicator: one explicit DDL sequence inside one
// SQLite transaction opened with BEGIN IMMEDIATE, with the validator_schema
// version row written in the same transaction. No GORM AutoMigrate, no ALTER
// chains, no migration framework.
//
// Version handling fails closed: a recorded version other than the current one
// aborts before any table is dropped, and peer tables are never touched.
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

		return validateValidatorSchema(ctx, conn)
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
// false when no validator_schema table exists yet (fresh or pre-versioning
// database). A present but malformed version table fails closed.
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
// evidence_row.exchange_id keeps ON DELETE SET NULL so evidence rows
// survive deletion of an individual exchange row.
var validatorSchemaStatements = []string{
	`CREATE TABLE test_run (
		test_run_id TEXT PRIMARY KEY,
		is_active INTEGER NOT NULL,
		state TEXT NOT NULL CHECK (state IN (
			'active_running',
			'invite_minted',
			'invite_accepted',
			'reverse_invite_solicited',
			'reverse_awaiting_invite',
			'reverse_invite_imported',
			'reverse_invite_accepted',
			'forward_share_sent',
			'capability_exercise',
			'reverse_awaiting_share',
			'terminal_pass',
			'terminal_fail',
			'interrupted',
			'created',
			'passive_running',
			'passive_complete'
		)),
		target_origin TEXT NOT NULL,
		target_host TEXT NOT NULL,
		discovery_url TEXT NOT NULL,
		jwks_uri TEXT NOT NULL,
		terminal_reason TEXT,
		finished_at INTEGER,
		overall_grade TEXT,
		manifest_schema TEXT NOT NULL,
		manifest_json TEXT,
		session_kind TEXT NOT NULL,
		bob_user_id TEXT,
		reverse_invite_token TEXT,
		reverse_invite_imported_at INTEGER,
		designated_share_with TEXT,
		reverse_share_provider_id TEXT,
		stats_written_at INTEGER,
		opt_in_stats INTEGER NOT NULL DEFAULT 0,
		opt_in_permanent INTEGER NOT NULL DEFAULT 0,
		opt_in_stats_channel TEXT,
		opt_in_stats_at INTEGER,
		opt_in_permanent_channel TEXT,
		opt_in_permanent_at INTEGER,
		retention_tier TEXT,
		retention_locked_at INTEGER,
		expires_at INTEGER,
		permanent_report_id TEXT UNIQUE,
		harvested_at INTEGER,
		harvested_session_artifacts_at INTEGER,
		harvest_reason TEXT,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	)`,
	`CREATE UNIQUE INDEX idx_test_run_one_active ON test_run (is_active) WHERE is_active = 1`,
	`CREATE INDEX idx_test_run_state ON test_run (state)`,
	`CREATE INDEX idx_test_run_session_kind ON test_run (session_kind)`,
	`CREATE INDEX idx_test_run_bob_user_id ON test_run (bob_user_id)`,
	`CREATE INDEX idx_test_run_expires_at ON test_run (expires_at)`,
	`CREATE INDEX idx_test_run_stats_heal ON test_run (stats_written_at) WHERE opt_in_stats = 1 AND stats_written_at IS NULL`,
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
	`CREATE UNIQUE INDEX idx_share_corr_outgoing_invite_slot
		ON share_correlation (test_run_id) WHERE role = 'outgoing_invite'`,
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
		req_body_raw BLOB,
		resp_body_raw BLOB,
		req_body_sha256 TEXT,
		resp_body_sha256 TEXT,
		req_body_bytes INTEGER,
		resp_body_bytes INTEGER,
		req_body_truncated INTEGER NOT NULL DEFAULT 0,
		resp_body_truncated INTEGER NOT NULL DEFAULT 0,
		grade TEXT,
		reason_codes TEXT,
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
		test_run_id TEXT NOT NULL REFERENCES test_run (test_run_id) ON DELETE RESTRICT,
		area TEXT NOT NULL,
		step TEXT NOT NULL,
		reason_code TEXT NOT NULL,
		severity TEXT NOT NULL,
		affects_grade INTEGER NOT NULL,
		payload_redacted TEXT,
		exchange_id INTEGER REFERENCES report_exchange (exchange_id) ON DELETE SET NULL,
		created_at INTEGER NOT NULL
	)`,
	`CREATE UNIQUE INDEX idx_evidence_row ON evidence_row (test_run_id, area, step, reason_code)`,
	`CREATE INDEX idx_evidence_row_area ON evidence_row (test_run_id, area)`,
	`CREATE TABLE dispatch_reservation (
		test_run_id TEXT PRIMARY KEY REFERENCES test_run (test_run_id) ON DELETE RESTRICT,
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
		created_at INTEGER NOT NULL,
		window_bucket INTEGER
	)`,
	`CREATE INDEX idx_stats_raw_host_hash ON stats_raw (host_hash)`,
	`CREATE INDEX idx_stats_raw_session_kind ON stats_raw (session_kind)`,
	`CREATE INDEX idx_stats_raw_platform ON stats_raw (platform)`,
	`CREATE INDEX idx_stats_raw_created_at ON stats_raw (created_at)`,
	`CREATE INDEX idx_stats_raw_window_bucket ON stats_raw (window_bucket)`,
	`CREATE TABLE stats_aggregate (
		host_hash TEXT PRIMARY KEY,
		total_sessions INTEGER NOT NULL,
		healthy_sessions INTEGER NOT NULL,
		last_platform TEXT NOT NULL,
		last_healthy INTEGER NOT NULL,
		first_seen_ts INTEGER NOT NULL,
		last_seen_ts INTEGER NOT NULL
	)`,
	`CREATE INDEX idx_stats_agg_last_seen ON stats_aggregate (last_seen_ts)`,
	`CREATE TABLE validator_schema (
		version INTEGER PRIMARY KEY
	)`,
	`INSERT INTO validator_schema (version) VALUES (1)`,
}
