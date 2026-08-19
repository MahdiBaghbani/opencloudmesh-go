// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

// This file pins the expected version-1 schema shape for validation. The data
// is deliberately redundant with validatorSchemaStatements in schema.go: the
// DDL creates the schema, this contract verifies a recorded version-1 database
// still matches it exactly, and the two must not share literals or the check
// would drift together with the DDL.

// Column type literals as the DDL declares them and PRAGMA table_info reports
// them. Compared case-insensitively during validation.
const (
	colTypeText    = "TEXT"
	colTypeInteger = "INTEGER"
)

// columnContract is the expected shape of one column in cid (declaration)
// order: name, declared type, nullability, default literal as reported by
// PRAGMA table_info, and primary-key position (0 when not part of the key).
type columnContract struct {
	name    string
	colType string
	notNull bool
	dflt    *string
	pk      int
}

// Default literals as SQLite reports them in PRAGMA table_info dflt_value.
var (
	columnDefaultZero      = "0"
	columnDefaultConfirmed = "'confirmed'"
)

// validatorTableContract lists every column of every validator-owned table in
// declaration order. A version-1 database whose shape differs in any column
// name, order, type, nullability, default, or key position is malformed and
// fails closed.
var validatorTableContract = map[string][]columnContract{
	tableTestRun: {
		{name: colTestRunID, colType: colTypeText, pk: 1},
		{name: colIsActive, colType: colTypeInteger, notNull: true},
		{name: colState, colType: colTypeText, notNull: true},
		{name: "target_origin", colType: colTypeText, notNull: true},
		{name: "target_host", colType: colTypeText, notNull: true},
		{name: "discovery_url", colType: colTypeText, notNull: true},
		{name: "jwks_uri", colType: colTypeText, notNull: true},
		{name: colTerminalReason, colType: colTypeText},
		{name: colFinishedAt, colType: colTypeInteger},
		{name: "overall_grade", colType: colTypeText},
		{name: "manifest_schema", colType: colTypeText, notNull: true},
		{name: "manifest_json", colType: colTypeText},
		{name: colSessionKind, colType: colTypeText, notNull: true},
		{name: "bob_user_id", colType: colTypeText},
		{name: "reverse_invite_token", colType: colTypeText},
		{name: "reverse_invite_imported_at", colType: colTypeInteger},
		{name: "designated_share_with", colType: colTypeText},
		{name: "reverse_share_provider_id", colType: colTypeText},
		{name: "stats_written_at", colType: colTypeInteger},
		{name: "opt_in_stats", colType: colTypeInteger, notNull: true, dflt: &columnDefaultZero},
		{name: "opt_in_permanent", colType: colTypeInteger, notNull: true, dflt: &columnDefaultZero},
		{name: "opt_in_stats_channel", colType: colTypeText},
		{name: "opt_in_stats_at", colType: colTypeInteger},
		{name: "opt_in_permanent_channel", colType: colTypeText},
		{name: "opt_in_permanent_at", colType: colTypeInteger},
		{name: "retention_tier", colType: colTypeText},
		{name: "retention_locked_at", colType: colTypeInteger},
		{name: "expires_at", colType: colTypeInteger},
		{name: "permanent_report_id", colType: colTypeText},
		{name: "harvested_at", colType: colTypeInteger},
		{name: "harvested_session_artifacts_at", colType: colTypeInteger},
		{name: "harvest_reason", colType: colTypeText},
		{name: colCreatedAt, colType: colTypeInteger, notNull: true},
		{name: colUpdatedAt, colType: colTypeInteger, notNull: true},
	},
	tableShareCorrelation: {
		{name: "id", colType: colTypeInteger, pk: 1},
		{name: colTestRunID, colType: colTypeText, notNull: true},
		{name: "role", colType: colTypeText, notNull: true},
		{name: "sender_host", colType: colTypeText, notNull: true},
		{name: colProviderID, colType: colTypeText, notNull: true},
		{name: colLocalIdentity, colType: colTypeText, notNull: true},
		{name: "share_id", colType: colTypeText},
		{name: "invite_id", colType: colTypeText},
		{name: "status", colType: colTypeText, notNull: true, dflt: &columnDefaultConfirmed},
		{name: colCreatedAt, colType: colTypeInteger, notNull: true},
	},
	tableStatsRaw: {
		{name: "id", colType: colTypeInteger, pk: 1},
		{name: "k", colType: colTypeText, notNull: true},
		{name: colHostHash, colType: colTypeText, notNull: true},
		{name: colSessionKind, colType: colTypeText, notNull: true},
		{name: "reverse_invite_exercised", colType: colTypeInteger, notNull: true},
		{name: "platform", colType: colTypeText, notNull: true},
		{name: "api_version", colType: colTypeText, notNull: true},
		{name: "grade_discovery", colType: colTypeText},
		{name: "grade_tls", colType: colTypeText},
		{name: "grade_jwks", colType: colTypeText},
		{name: "grade_httpsig", colType: colTypeText},
		{name: "grade_sharing", colType: colTypeText},
		{name: "grade_notification", colType: colTypeText},
		{name: "grade_token", colType: colTypeText},
		{name: "grade_capability", colType: colTypeText},
		{name: colCreatedAt, colType: colTypeInteger, notNull: true},
		{name: "window_bucket", colType: colTypeInteger},
	},
	tableStatsAggregate: {
		{name: colHostHash, colType: colTypeText, pk: 1},
		{name: "total_sessions", colType: colTypeInteger, notNull: true},
		{name: "healthy_sessions", colType: colTypeInteger, notNull: true},
		{name: "last_platform", colType: colTypeText, notNull: true},
		{name: "last_healthy", colType: colTypeInteger, notNull: true},
		{name: "first_seen_ts", colType: colTypeInteger, notNull: true},
		{name: "last_seen_ts", colType: colTypeInteger, notNull: true},
	},
	tableReportExchange: {
		{name: colExchangeID, colType: colTypeInteger, pk: 1},
		{name: colTestRunID, colType: colTypeText, notNull: true},
		{name: "seq", colType: colTypeInteger, notNull: true},
		{name: "captured_at", colType: colTypeInteger, notNull: true},
		{name: "started_at", colType: colTypeInteger},
		{name: "ended_at", colType: colTypeInteger},
		{name: "duration_ms", colType: colTypeInteger},
		{name: "direction", colType: colTypeText, notNull: true},
		{name: "actor", colType: colTypeText},
		{name: colLocalIdentity, colType: colTypeText},
		{name: "corr_role", colType: colTypeText},
		{name: "leg", colType: colTypeText},
		{name: "endpoint_id", colType: colTypeText, notNull: true},
		{name: "method", colType: colTypeText, notNull: true},
		{name: "url", colType: colTypeText, notNull: true},
		{name: "host", colType: colTypeText},
		{name: "status_code", colType: colTypeInteger},
		{name: "http_version", colType: colTypeText},
		{name: "error_text", colType: colTypeText},
		{name: "request_id", colType: colTypeText},
		{name: "req_headers_json", colType: colTypeText},
		{name: "resp_headers_json", colType: colTypeText},
		{name: "sig_raw", colType: colTypeText},
		{name: "sig_key_id", colType: colTypeText},
		{name: "sig_algorithm", colType: colTypeText},
		{name: "sig_scheme", colType: colTypeText},
		{name: "sig_valid", colType: colTypeInteger},
		{name: "digest", colType: colTypeText},
		{name: "req_body_redacted", colType: colTypeText},
		{name: "resp_body_redacted", colType: colTypeText},
		{name: "req_body_raw", colType: "BLOB"},
		{name: "resp_body_raw", colType: "BLOB"},
		{name: "req_body_sha256", colType: colTypeText},
		{name: "resp_body_sha256", colType: colTypeText},
		{name: "req_body_bytes", colType: colTypeInteger},
		{name: "resp_body_bytes", colType: colTypeInteger},
		{name: "req_body_truncated", colType: colTypeInteger, notNull: true, dflt: &columnDefaultZero},
		{name: "resp_body_truncated", colType: colTypeInteger, notNull: true, dflt: &columnDefaultZero},
		{name: "grade", colType: colTypeText},
		{name: "reason_codes", colType: colTypeText},
		{name: colCreatedAt, colType: colTypeInteger, notNull: true},
	},
	tableEvidenceRow: {
		{name: "id", colType: colTypeInteger, pk: 1},
		{name: colTestRunID, colType: colTypeText, notNull: true},
		{name: colArea, colType: colTypeText, notNull: true},
		{name: "step", colType: colTypeText, notNull: true},
		{name: "reason_code", colType: colTypeText, notNull: true},
		{name: "severity", colType: colTypeText, notNull: true},
		{name: "affects_grade", colType: colTypeInteger, notNull: true},
		{name: "payload_redacted", colType: colTypeText},
		{name: colExchangeID, colType: colTypeInteger},
		{name: colCreatedAt, colType: colTypeInteger, notNull: true},
	},
	tableDispatchReservation: {
		{name: colTestRunID, colType: colTypeText, pk: 1},
		{name: colProviderID, colType: colTypeText, notNull: true},
		{name: "webdav_id", colType: colTypeText, notNull: true},
		{name: "shared_secret", colType: colTypeText, notNull: true},
		{name: "receiver_host", colType: colTypeText, notNull: true},
		{name: "share_with", colType: colTypeText, notNull: true},
		{name: "probe_file_path", colType: colTypeText, notNull: true},
		{name: "status", colType: colTypeText, notNull: true},
		{name: "outgoing_share_id", colType: colTypeText},
		{name: "remote_sent_at", colType: colTypeInteger},
		{name: "cas_committed_at", colType: colTypeInteger},
		{name: colCreatedAt, colType: colTypeInteger, notNull: true},
		{name: colUpdatedAt, colType: colTypeInteger},
	},
	tableValidatorSchema: {
		{name: "version", colType: colTypeInteger, pk: 1},
	},
}

// testRunStateCollation is the only collation accepted on test_run.state: the
// SQLite default BINARY. The canonical DDL declares no COLLATE clause, and an
// explicit COLLATE BINARY is equivalent. NOCASE or RTRIM would make state
// name comparisons case- or trailing-space-insensitive, weakening the exact
// state CHECK, so any non-BINARY collation fails closed.
const testRunStateCollation = "BINARY"

// dormantTestRunStates are retired state names that must never appear in the
// test_run.state CHECK of a final version-1 schema.
var dormantTestRunStates = []string{
	"awaiting_return_share",
	"reverse_share_accepted",
	"reverse_capability_exercise",
	"passive_done",
}

// indexContract pins one named index: the table it belongs to, uniqueness, the
// exact indexed columns in key order, and the normalized partial predicate
// (empty when the index is not partial).
type indexContract struct {
	name    string
	table   string
	unique  bool
	columns []string
	partial string
}

// validatorIndexContract is the full set of named indexes a version-1 database
// must carry. Inline UNIQUE column constraints are covered separately by
// validatorUniqueColumns because SQLite materializes them as auto-indexes.
var validatorIndexContract = []indexContract{
	{name: "idx_test_run_one_active", table: tableTestRun, unique: true, columns: []string{colIsActive}, partial: "is_active = 1"},
	{name: "idx_test_run_state", table: tableTestRun, columns: []string{colState}},
	{name: "idx_test_run_session_kind", table: tableTestRun, columns: []string{colSessionKind}},
	{name: "idx_test_run_bob_user_id", table: tableTestRun, columns: []string{"bob_user_id"}},
	{name: "idx_test_run_expires_at", table: tableTestRun, columns: []string{"expires_at"}},
	{
		name: "idx_test_run_stats_heal", table: tableTestRun,
		columns: []string{"stats_written_at"}, partial: "opt_in_stats = 1 AND stats_written_at IS NULL",
	},
	{
		name: "idx_share_corr_unique", table: tableShareCorrelation, unique: true,
		columns: []string{colTestRunID, "role", "sender_host", colProviderID, colLocalIdentity},
	},
	{
		name: "idx_share_corr_outgoing_invite_slot", table: tableShareCorrelation, unique: true,
		columns: []string{colTestRunID}, partial: "role = 'outgoing_invite'",
	},
	{
		name: "idx_share_corr_incoming_invite_slot", table: tableShareCorrelation, unique: true,
		columns: []string{colTestRunID}, partial: "role = 'incoming_invite'",
	},
	{name: "idx_report_ex_run_seq", table: tableReportExchange, unique: true, columns: []string{colTestRunID, "seq"}},
	{name: "idx_report_ex_run_captured", table: tableReportExchange, columns: []string{colTestRunID, "captured_at"}},
	{name: "idx_report_ex_run_leg", table: tableReportExchange, columns: []string{colTestRunID, "leg"}},
	{name: "idx_report_ex_run_identity", table: tableReportExchange, columns: []string{colTestRunID, colLocalIdentity}},
	{name: "idx_report_ex_run_endpoint", table: tableReportExchange, columns: []string{colTestRunID, "endpoint_id"}},
	{
		name: "idx_report_ex_idem", table: tableReportExchange, unique: true,
		columns: []string{colTestRunID, "direction", "request_id"},
		partial: "request_id IS NOT NULL AND request_id != ''",
	},
	{
		name: "idx_evidence_row", table: tableEvidenceRow, unique: true,
		columns: []string{colTestRunID, colArea, "step", "reason_code"},
	},
	{name: "idx_evidence_row_area", table: tableEvidenceRow, columns: []string{colTestRunID, colArea}},
	{name: "idx_stats_raw_host_hash", table: tableStatsRaw, columns: []string{colHostHash}},
	{name: "idx_stats_raw_session_kind", table: tableStatsRaw, columns: []string{colSessionKind}},
	{name: "idx_stats_raw_platform", table: tableStatsRaw, columns: []string{"platform"}},
	{name: "idx_stats_raw_created_at", table: tableStatsRaw, columns: []string{colCreatedAt}},
	{name: "idx_stats_raw_window_bucket", table: tableStatsRaw, columns: []string{"window_bucket"}},
	{name: "idx_stats_agg_last_seen", table: tableStatsAggregate, columns: []string{"last_seen_ts"}},
}

// validatorUniqueColumns pins the inline UNIQUE column constraints of the
// version-1 schema. SQLite enforces them through auto-indexes, so they are
// validated by probing for a single-column unique index instead of by name.
var validatorUniqueColumns = map[string][]string{
	tableTestRun:             {"permanent_report_id"},
	tableStatsRaw:            {"k"},
	tableDispatchReservation: {colProviderID, "webdav_id"},
}

type fkExpectation struct {
	referencedTable  string
	referencedColumn string
	onUpdate         string
	onDelete         string
}

// validatorForeignKeys pins the exact FK contract per table/column: referenced
// table and column plus both actions. SQLite reports an unspecified action as
// NO ACTION. Validator-owned child tables cascade on test_run delete;
// evidence_row.exchange_id keeps SET NULL. Tables absent from this map must
// have no foreign keys at all.
var validatorForeignKeys = map[string]map[string]fkExpectation{
	tableShareCorrelation: {
		colTestRunID: {tableTestRun, colTestRunID, fkCascade, fkCascade},
	},
	tableReportExchange: {
		colTestRunID: {tableTestRun, colTestRunID, fkCascade, fkCascade},
	},
	tableEvidenceRow: {
		colTestRunID:  {tableTestRun, colTestRunID, fkNoAction, fkCascade},
		colExchangeID: {tableReportExchange, colExchangeID, fkNoAction, fkSetNull},
	},
	tableDispatchReservation: {
		colTestRunID: {tableTestRun, colTestRunID, fkNoAction, fkCascade},
	},
}
