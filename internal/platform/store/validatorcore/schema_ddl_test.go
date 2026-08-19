// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// ocmgo:file-length-ignore: validator DDL contract and constraint coverage

package validatorcore

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"gorm.io/gorm"
	gormschema "gorm.io/gorm/schema"
)

func TestTestRunStateCheck_ExactStates(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	sqlText := tableSQL(t, db, "test_run")

	// The DDL must name exactly the live state list: every live value present,
	// every dormant value absent.
	for _, state := range testRunStates {
		if !strings.Contains(sqlText, "'"+state+"'") {
			t.Fatalf("test_run CHECK missing live state %q", state)
		}
	}

	for _, state := range dormantTestRunStates {
		if strings.Contains(sqlText, "'"+state+"'") {
			t.Fatalf("test_run CHECK must not contain dormant state %q", state)
		}
	}

	newRun := func(id, state string) TestRun {
		return TestRun{
			TestRunID:      id,
			State:          state,
			TargetOrigin:   "https://t.example",
			TargetHost:     "t.example",
			DiscoveryURL:   "https://t.example/.well-known/ocm",
			JwksURI:        "https://t.example/jwks.json",
			ManifestSchema: "ocm-validator-manifest/v1",
			SessionKind:    SessionKindPassiveOnly,
			CreatedAt:      1,
			UpdatedAt:      1,
		}
	}

	// Every live state name must be accepted by the CHECK constraint.
	for i, state := range testRunStates {
		run := newRun(fmt.Sprintf("run-live-%d", i), state)
		if err := db.Create(&run).Error; err != nil {
			t.Fatalf("live state %q must be accepted: %v", state, err)
		}
	}

	// Every dormant state name must be rejected.
	for i, state := range dormantTestRunStates {
		run := newRun(fmt.Sprintf("run-dormant-%d", i), state)
		if err := db.Create(&run).Error; err == nil {
			t.Fatalf("dormant state %q must be rejected by the CHECK constraint", state)
		}
	}

	// Arbitrary values outside the live list must be rejected.
	for i, state := range []string{"", "RUNNING", "terminal_unknown", "active"} {
		run := newRun(fmt.Sprintf("run-arbitrary-%d", i), state)
		if err := db.Create(&run).Error; err == nil {
			t.Fatalf("arbitrary state %q must be rejected by the CHECK constraint", state)
		}
	}
}

func TestTestRun_FinalColumns(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "test_run")

	expected := []string{
		"test_run_id", "is_active", "state", "target_origin", "target_host",
		"discovery_url", "jwks_uri", "terminal_reason", "finished_at",
		"overall_grade", "manifest_schema", "manifest_json", "session_kind",
		"created_at", "updated_at",
		"bob_user_id", "reverse_invite_token", "reverse_invite_imported_at",
		"designated_share_with", "reverse_share_provider_id", "stats_written_at",
		"opt_in_stats", "opt_in_permanent", "opt_in_stats_channel", "opt_in_stats_at",
		"opt_in_permanent_channel", "opt_in_permanent_at", "retention_tier",
		"retention_locked_at", "expires_at", "permanent_report_id", "harvested_at",
		"harvested_session_artifacts_at", "harvest_reason",
	}

	for _, col := range expected {
		if _, ok := info[col]; !ok {
			t.Fatalf("test_run missing column %s", col)
		}
	}

	forbidden := []string{"is_permanent", "alice_storage_root", "probe_file_path"}

	for _, col := range forbidden {
		if _, ok := info[col]; ok {
			t.Fatalf("test_run must not have column %s", col)
		}
	}

	if info["test_run_id"].PK != 1 {
		t.Fatal("test_run_id must be the primary key")
	}

	if info["bob_user_id"].NotNull {
		t.Fatal("bob_user_id must be nullable")
	}

	if !info["opt_in_stats"].NotNull || !info["opt_in_permanent"].NotNull {
		t.Fatal("opt_in_stats and opt_in_permanent must be NOT NULL")
	}
}

func TestTestRun_OneActivePartialUniqueIndex(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	var indexSQL string

	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_test_run_one_active'",
	).Scan(&indexSQL).Error; err != nil {
		t.Fatalf("read index sql: %v", err)
	}

	if indexSQL == "" {
		t.Fatal("idx_test_run_one_active index missing")
	}

	if !strings.Contains(strings.ToUpper(indexSQL), "WHERE") {
		t.Fatalf("idx_test_run_one_active must be partial: %s", indexSQL)
	}

	createTestRun(t, db, "run-active-1")
	mustExec(t, db, "UPDATE test_run SET is_active = TRUE WHERE test_run_id = 'run-active-1'")
	createTestRun(t, db, "run-active-2")

	if err := db.Exec("UPDATE test_run SET is_active = TRUE WHERE test_run_id = 'run-active-2'").Error; err == nil {
		t.Fatal("second active run must violate the partial unique index")
	}
}

func TestStatsRawK_NotNullUnique(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "stats_raw")

	k, ok := info["k"]
	if !ok {
		t.Fatal("stats_raw missing column k")
	}

	if !k.NotNull {
		t.Fatal("stats_raw.k must be NOT NULL")
	}

	if k.DfltValue != nil {
		t.Fatalf("stats_raw.k must have no default, got %v", *k.DfltValue)
	}

	row := StatsRaw{
		K:           "k-dup",
		HostHash:    "host-1",
		SessionKind: SessionKindPassiveOnly,
		Platform:    "nextcloud",
		APIVersion:  "1",
		CreatedAt:   1,
	}

	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("insert stats_raw with k: %v", err)
	}

	dup := row
	dup.ID = 0

	if err := db.Create(&dup).Error; err == nil {
		t.Fatal("duplicate stats_raw.k must be rejected")
	}

	err := db.Exec(`INSERT INTO stats_raw
		(host_hash, session_kind, reverse_invite_exercised, platform, api_version, created_at)
		VALUES ('host-2', 'passive_only', FALSE, 'nextcloud', '1', 1)`).Error
	if err == nil {
		t.Fatal("stats_raw insert without k must be rejected (NOT NULL)")
	}
}

func TestStatsAggregate_Schema(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "stats_aggregate")

	// Exact column set in declaration order: host_hash PK plus six NOT NULL
	// metric columns, nothing else. SQLite reports a TEXT PRIMARY KEY column
	// as nullable in PRAGMA table_info (the historical SQLite quirk), so
	// host_hash is pinned by key position and type, not by the NOT NULL flag.
	expected := []struct {
		name string
		pk   int
	}{
		{"host_hash", 1},
		{"total_sessions", 0},
		{"healthy_sessions", 0},
		{"last_platform", 0},
		{"last_healthy", 0},
		{"first_seen_ts", 0},
		{"last_seen_ts", 0},
	}

	if len(info) != len(expected) {
		t.Fatalf("stats_aggregate has %d columns, want %d", len(info), len(expected))
	}

	for _, col := range expected {
		got, ok := info[col.name]
		if !ok {
			t.Fatalf("stats_aggregate missing column %s", col.name)
		}

		if got.PK != col.pk {
			t.Fatalf("stats_aggregate.%s pk = %d, want %d", col.name, got.PK, col.pk)
		}

		if got.DfltValue != nil {
			t.Fatalf("stats_aggregate.%s must have no default, got %v", col.name, *got.DfltValue)
		}

		if col.name == "host_hash" {
			continue
		}

		if !got.NotNull {
			t.Fatalf("stats_aggregate.%s must be NOT NULL", col.name)
		}
	}

	if got := info["host_hash"]; !strings.EqualFold(got.Type, "TEXT") {
		t.Fatalf("stats_aggregate.host_hash must be TEXT, got %q", got.Type)
	}

	// The locked last-seen index must exist with exactly last_seen_ts as its
	// single indexed column.
	var indexSQL string

	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?", "idx_stats_agg_last_seen",
	).Scan(&indexSQL).Error; err != nil {
		t.Fatalf("read idx_stats_agg_last_seen: %v", err)
	}

	if indexSQL == "" {
		t.Fatal("index idx_stats_agg_last_seen missing")
	}

	if strings.Contains(strings.ToUpper(indexSQL), "UNIQUE") {
		t.Fatalf("idx_stats_agg_last_seen must not be UNIQUE: %s", indexSQL)
	}

	var indexed []struct {
		Seqno int    `gorm:"column:seqno"`
		CID   int    `gorm:"column:cid"`
		Name  string `gorm:"column:name"`
	}

	if err := db.Raw("PRAGMA index_info(idx_stats_agg_last_seen)").Scan(&indexed).Error; err != nil {
		t.Fatalf("PRAGMA index_info(idx_stats_agg_last_seen): %v", err)
	}

	if len(indexed) != 1 || indexed[0].Name != "last_seen_ts" {
		t.Fatalf("idx_stats_agg_last_seen columns = %+v, want [last_seen_ts]", indexed)
	}
}

func TestStatsAggregate_Constraints(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	row := StatsAggregate{
		HostHash:        "host-agg",
		TotalSessions:   3,
		HealthySessions: 2,
		LastPlatform:    "nextcloud",
		LastHealthy:     true,
		FirstSeenTS:     10,
		LastSeenTS:      30,
	}

	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("insert stats_aggregate: %v", err)
	}

	// host_hash is the primary key: a second row with the same host_hash must
	// be rejected.
	dup := row
	if err := db.Create(&dup).Error; err == nil {
		t.Fatal("duplicate stats_aggregate.host_hash must be rejected")
	}

	// Every metric column is NOT NULL: omitting one must be rejected.
	err := db.Exec(`INSERT INTO stats_aggregate
		(host_hash, total_sessions, healthy_sessions, last_platform, last_healthy, first_seen_ts)
		VALUES ('host-agg-2', 1, 1, 'nextcloud', TRUE, 1)`).Error
	if err == nil {
		t.Fatal("stats_aggregate insert without last_seen_ts must be rejected (NOT NULL)")
	}
}

var reportExchangeColumns = []string{
	"exchange_id", "test_run_id", "seq", "captured_at", "started_at", "ended_at",
	"duration_ms", "direction", "actor", "local_identity", "corr_role", "leg",
	"endpoint_id", "method", "url", "host", "status_code", "http_version",
	"error_text", "request_id", "req_headers_json", "resp_headers_json",
	"sig_raw", "sig_key_id", "sig_algorithm", "sig_scheme", "sig_valid",
	"digest", "req_body_redacted", "resp_body_redacted", "req_body_raw",
	"resp_body_raw", "req_body_sha256", "resp_body_sha256", "req_body_bytes",
	"resp_body_bytes", "req_body_truncated", "resp_body_truncated", "grade",
	"reason_codes", "created_at",
}

func TestReportExchange_ColumnsAndFK(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "report_exchange")

	if info["exchange_id"].PK != 1 {
		t.Fatal("exchange_id must be the primary key")
	}

	if _, ok := info["id"]; ok {
		t.Fatal("report_exchange must not have an id column")
	}

	if !info["test_run_id"].NotNull {
		t.Fatal("report_exchange.test_run_id must be NOT NULL")
	}

	if info["actor"].NotNull {
		t.Fatal("report_exchange.actor must be nullable")
	}

	if !info["endpoint_id"].NotNull {
		t.Fatal("report_exchange.endpoint_id must be NOT NULL")
	}

	for _, col := range reportExchangeColumns {
		if _, ok := info[col]; !ok {
			t.Fatalf("report_exchange missing column %s", col)
		}
	}

	fks := foreignKeys(t, db, "report_exchange")
	fk := findFK(fks, colTestRunID)

	if fk == nil {
		t.Fatal("report_exchange missing FK on test_run_id")
	}

	if fk.Table != "test_run" || fk.OnUpdate != "CASCADE" || fk.OnDelete != "CASCADE" {
		t.Fatalf("report_exchange FK = %+v, want test_run CASCADE/CASCADE", fk)
	}
}

func TestReportExchange_BodyColumnTypes(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "report_exchange")

	for _, col := range []string{"req_body_raw", "resp_body_raw"} {
		if !strings.EqualFold(info[col].Type, "BLOB") {
			t.Fatalf("report_exchange.%s must be BLOB, got %q", col, info[col].Type)
		}
	}

	for _, col := range []string{"req_body_truncated", "resp_body_truncated"} {
		if !info[col].NotNull || info[col].DfltValue == nil || *info[col].DfltValue != "0" {
			t.Fatalf("report_exchange.%s must be NOT NULL DEFAULT 0, got %+v", col, info[col])
		}
	}
}

func TestReportExchange_LockedIndexNames(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	for _, index := range []string{
		"idx_report_ex_run_seq",
		"idx_report_ex_run_captured",
		"idx_report_ex_run_leg",
		"idx_report_ex_run_identity",
		"idx_report_ex_run_endpoint",
		"idx_report_ex_idem",
	} {
		var sqlText string

		if err := db.Raw(
			"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?", index,
		).Scan(&sqlText).Error; err != nil {
			t.Fatalf("read index %s: %v", index, err)
		}

		if sqlText == "" {
			t.Fatalf("index %s missing", index)
		}
	}
}

func insertReportExchange(t *testing.T, db *gorm.DB, seq int, requestID *string) error {
	t.Helper()

	args := []any{"run-rex", seq, 1, "out", "validator", "discovery", "GET", "https://t.example/x", 1}
	reqExpr := "NULL"

	if requestID != nil {
		reqExpr = "?"

		args = append(args, *requestID)
	}

	return db.Exec(`INSERT INTO report_exchange
		(test_run_id, seq, captured_at, direction, actor, endpoint_id, method, url, created_at, request_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, `+reqExpr+`)`, args...).Error
}

func TestReportExchange_Constraints(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	createTestRun(t, db, "run-rex")

	if err := insertReportExchange(t, db, 1, nil); err != nil {
		t.Fatalf("insert exchange: %v", err)
	}

	if err := insertReportExchange(t, db, 1, nil); err == nil {
		t.Fatal("duplicate (test_run_id, seq) must be rejected")
	}

	reqID := "req-1"

	if err := insertReportExchange(t, db, 2, &reqID); err != nil {
		t.Fatalf("insert exchange with request_id: %v", err)
	}

	if err := insertReportExchange(t, db, 3, &reqID); err == nil {
		t.Fatal("duplicate nonempty (test_run_id, direction, request_id) must be rejected")
	}

	empty := ""

	if err := insertReportExchange(t, db, 4, &empty); err != nil {
		t.Fatalf("insert exchange with empty request_id: %v", err)
	}

	if err := insertReportExchange(t, db, 5, &empty); err != nil {
		t.Fatal("empty request_id rows must not collide in the idempotency index")
	}

	if err := insertReportExchange(t, db, 6, nil); err != nil {
		t.Fatal("NULL request_id rows must not collide in the idempotency index")
	}

	// actor is nullable in the final contract.
	err := db.Exec(`INSERT INTO report_exchange
		(test_run_id, seq, captured_at, direction, actor, endpoint_id, method, url, created_at)
		VALUES ('run-rex', 7, 1, 'in', NULL, 'discovery', 'GET', 'https://t.example/y', 1)`).Error
	if err != nil {
		t.Fatalf("NULL actor must be accepted: %v", err)
	}

	// endpoint_id is NOT NULL in the final contract.
	err = db.Exec(`INSERT INTO report_exchange
		(test_run_id, seq, captured_at, direction, actor, method, url, created_at)
		VALUES ('run-rex', 8, 1, 'in', NULL, 'GET', 'https://t.example/z', 1)`).Error
	if err == nil {
		t.Fatal("omitting endpoint_id must be rejected")
	}
}

func TestEvidenceRow_ColumnsAndFK(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "evidence_row")

	if info["id"].PK != 1 {
		t.Fatal("evidence_row.id must be the primary key")
	}

	for _, col := range []string{"test_run_id", "area", "step", "reason_code", "severity", "affects_grade"} {
		if !info[col].NotNull {
			t.Fatalf("evidence_row.%s must be NOT NULL", col)
		}
	}

	if info["payload_redacted"].NotNull || info["exchange_id"].NotNull {
		t.Fatal("payload_redacted and exchange_id must be nullable")
	}

	var uniqueSQL string

	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_evidence_row'",
	).Scan(&uniqueSQL).Error; err != nil {
		t.Fatalf("read idx_evidence_row: %v", err)
	}

	if uniqueSQL == "" || !strings.Contains(strings.ToUpper(uniqueSQL), "UNIQUE") {
		t.Fatalf("idx_evidence_row must be a unique index: %q", uniqueSQL)
	}

	fks := foreignKeys(t, db, "evidence_row")
	runFK := findFK(fks, "test_run_id")

	if runFK == nil || runFK.Table != "test_run" || runFK.OnDelete != "CASCADE" {
		t.Fatalf("evidence_row test_run FK = %+v, want test_run CASCADE", runFK)
	}

	exFK := findFK(fks, "exchange_id")

	if exFK == nil || exFK.Table != "report_exchange" || exFK.OnDelete != "SET NULL" {
		t.Fatalf("evidence_row exchange FK = %+v, want report_exchange SET NULL", exFK)
	}
}

func insertEvidenceRow(t *testing.T, db *gorm.DB, step string) error {
	t.Helper()

	return db.Exec(`INSERT INTO evidence_row
		(test_run_id, area, step, reason_code, severity, affects_grade, exchange_id, created_at)
		VALUES ('run-ev', 'http', ?, 'timeout', 'important', TRUE, 1, 1)`, step).Error
}

func TestEvidenceRow_Constraints(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	createTestRun(t, db, "run-ev")
	mustExec(t, db, `INSERT INTO report_exchange
		(test_run_id, seq, captured_at, direction, actor, endpoint_id, method, url, created_at)
		VALUES ('run-ev', 1, 1, 'out', 'validator', 'discovery', 'GET', 'https://t.example/x', 1)`)

	if err := insertEvidenceRow(t, db, "request"); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}

	if err := insertEvidenceRow(t, db, "request"); err == nil {
		t.Fatal("duplicate (test_run_id, area, step, reason_code) must be rejected")
	}

	if err := insertEvidenceRow(t, db, "response"); err != nil {
		t.Fatalf("insert second evidence: %v", err)
	}

	mustExec(t, db, "DELETE FROM report_exchange WHERE exchange_id = 1")

	var nullCount int64

	mustQueryCount(t, db,
		"SELECT COUNT(*) FROM evidence_row WHERE test_run_id = 'run-ev' AND exchange_id IS NULL",
		&nullCount)

	if nullCount != 2 {
		t.Fatalf("exchange delete must SET NULL on evidence rows, got %d nulled", nullCount)
	}

	// Validator-owned child rows cascade with their test_run.
	mustExec(t, db, "DELETE FROM test_run WHERE test_run_id = 'run-ev'")

	var evCount int64

	mustQueryCount(t, db, "SELECT COUNT(*) FROM evidence_row WHERE test_run_id = 'run-ev'", &evCount)

	if evCount != 0 {
		t.Fatalf("test_run delete must cascade to evidence rows, %d remain", evCount)
	}
}

func TestDispatchReservation_Schema(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "dispatch_reservation")

	if info["test_run_id"].PK != 1 {
		t.Fatal("dispatch_reservation.test_run_id must be the primary key")
	}

	for _, col := range []string{
		"provider_id", "webdav_id", "shared_secret", "receiver_host",
		"share_with", "probe_file_path", "status", "created_at",
	} {
		if !info[col].NotNull {
			t.Fatalf("dispatch_reservation.%s must be NOT NULL", col)
		}
	}

	for _, col := range []string{"outgoing_share_id", "remote_sent_at", "cas_committed_at", "updated_at"} {
		if info[col].NotNull {
			t.Fatalf("dispatch_reservation.%s must be nullable", col)
		}
	}

	fks := foreignKeys(t, db, "dispatch_reservation")
	fk := findFK(fks, "test_run_id")

	if fk == nil || fk.Table != "test_run" || fk.OnDelete != "CASCADE" {
		t.Fatalf("dispatch_reservation FK = %+v, want test_run CASCADE", fk)
	}
}

func insertReservation(t *testing.T, db *gorm.DB, runID, providerID, webdavID string) error {
	t.Helper()

	return db.Exec(`INSERT INTO dispatch_reservation
		(test_run_id, provider_id, webdav_id, shared_secret, receiver_host, share_with, probe_file_path, status, created_at)
		VALUES (?, ?, ?, 'secret', 'receiver.example', 'bob', '/probe.bin', 'dispatch_reserved', 1)`,
		runID, providerID, webdavID).Error
}

func TestDispatchReservation_Constraints(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	createTestRun(t, db, "run-disp-1")
	createTestRun(t, db, "run-disp-2")
	createTestRun(t, db, "run-disp-3")

	if err := insertReservation(t, db, "run-disp-1", "prov-1", "wd-1"); err != nil {
		t.Fatalf("insert reservation: %v", err)
	}

	if err := insertReservation(t, db, "run-disp-1", "prov-2", "wd-2"); err == nil {
		t.Fatal("duplicate test_run_id must be rejected (PK)")
	}

	if err := insertReservation(t, db, "run-disp-2", "prov-1", "wd-2"); err == nil {
		t.Fatal("duplicate provider_id must be rejected (UNIQUE)")
	}

	if err := insertReservation(t, db, "run-disp-3", "prov-2", "wd-1"); err == nil {
		t.Fatal("duplicate webdav_id must be rejected (UNIQUE)")
	}

	if err := insertReservation(t, db, "run-disp-2", "prov-2", "wd-2"); err != nil {
		t.Fatalf("insert second reservation: %v", err)
	}

	// Validator-owned child rows cascade with their test_run; the reservation
	// on run-disp-2 must survive.
	mustExec(t, db, "DELETE FROM test_run WHERE test_run_id = 'run-disp-1'")

	var resCount int64

	mustQueryCount(t, db, "SELECT COUNT(*) FROM dispatch_reservation", &resCount)

	if resCount != 1 {
		t.Fatalf("dispatch_reservation rows = %d, want 1 (cascade removes only run-disp-1)", resCount)
	}
}

func TestShareCorrelation_ColumnsAndFK(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "share_correlation")

	if info["id"].PK != 1 {
		t.Fatal("share_correlation.id must be the primary key")
	}

	if !info["test_run_id"].NotNull {
		t.Fatal("share_correlation.test_run_id must be NOT NULL")
	}

	if info["local_identity"].DfltValue != nil {
		t.Fatalf("local_identity must have no database default, got %v", *info["local_identity"].DfltValue)
	}

	fks := foreignKeys(t, db, "share_correlation")
	fk := findFK(fks, "test_run_id")

	if fk == nil || fk.Table != "test_run" || fk.OnUpdate != "CASCADE" || fk.OnDelete != "CASCADE" {
		t.Fatalf("share_correlation FK = %+v, want test_run CASCADE/CASCADE", fk)
	}
}

func newCorrelation(role, providerID, identity string) ShareCorrelation {
	return ShareCorrelation{
		TestRunID:     "run-corr",
		Role:          role,
		SenderHost:    "sender.example",
		ProviderID:    providerID,
		LocalIdentity: identity,
		Status:        "ok",
		CreatedAt:     1,
	}
}

func TestShareCorrelation_RoleSlotsAndComposite(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	createTestRun(t, db, "run-corr")

	outgoing := newCorrelation(RoleOutgoingInvite, "prov-a", "alice")

	if err := db.Create(&outgoing).Error; err != nil {
		t.Fatalf("insert outgoing invite: %v", err)
	}

	second := newCorrelation(RoleOutgoingInvite, "prov-b", "bob")

	if err := db.Create(&second).Error; err == nil {
		t.Fatal("second outgoing_invite slot row must be rejected")
	}

	incoming := newCorrelation(RoleIncomingInvite, "prov-c", "carol")

	if err := db.Create(&incoming).Error; err != nil {
		t.Fatalf("insert incoming invite: %v", err)
	}

	incoming2 := newCorrelation(RoleIncomingInvite, "prov-d", "dave")

	if err := db.Create(&incoming2).Error; err == nil {
		t.Fatal("second incoming_invite slot row must be rejected")
	}

	nonSlot1 := newCorrelation(RoleOutgoingToTarget, "prov-e", "erin")
	nonSlot2 := newCorrelation(RoleOutgoingToTarget, "prov-f", "frank")

	if err := db.Create(&nonSlot1).Error; err != nil {
		t.Fatalf("insert non-slot row: %v", err)
	}

	if err := db.Create(&nonSlot2).Error; err != nil {
		t.Fatal("non-slot roles must allow multiple rows per run")
	}

	dupComposite := newCorrelation(RoleOutgoingToTarget, "prov-e", "erin")

	if err := db.Create(&dupComposite).Error; err == nil {
		t.Fatal("duplicate composite (test_run_id, role, sender_host, provider_id, local_identity) must be rejected")
	}
}

func TestShareCorrelation_LockedSlotIndexNames(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	for _, index := range []string{
		"idx_share_corr_outgoing_invite_slot",
		"idx_share_corr_incoming_invite_slot",
	} {
		var sqlText string

		if err := db.Raw(
			"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?", index,
		).Scan(&sqlText).Error; err != nil {
			t.Fatalf("read index %s: %v", index, err)
		}

		if sqlText == "" || !strings.Contains(strings.ToUpper(sqlText), "UNIQUE") {
			t.Fatalf("index %s must exist as a unique slot index, got %q", index, sqlText)
		}
	}
}

// TestShareCorrelation_GORMIndexTagsMatchContract proves the ShareCorrelation
// GORM tags resolve to exactly the share_correlation indexes pinned by
// validatorIndexContract: name, uniqueness, column order, and partial
// predicate all agree.
func TestShareCorrelation_GORMIndexTagsMatchContract(t *testing.T) {
	t.Parallel()

	parsed, err := gormschema.Parse(&ShareCorrelation{}, &sync.Map{}, gormschema.NamingStrategy{})
	if err != nil {
		t.Fatalf("parse ShareCorrelation: %v", err)
	}

	indexes := map[string]*gormschema.Index{}

	for _, index := range parsed.ParseIndexes() {
		indexes[index.Name] = index
	}

	for _, want := range validatorIndexContract {
		if want.table != tableShareCorrelation {
			continue
		}

		index, ok := indexes[want.name]
		if !ok {
			t.Fatalf("ShareCorrelation GORM tags missing index %s", want.name)
		}

		if unique := index.Class == "UNIQUE"; unique != want.unique {
			t.Fatalf("index %s unique = %v, want %v", want.name, unique, want.unique)
		}

		if index.Where != want.partial {
			t.Fatalf("index %s where = %q, want %q", want.name, index.Where, want.partial)
		}

		var columns []string

		for _, field := range index.Fields {
			columns = append(columns, field.DBName)
		}

		if !slices.Equal(columns, want.columns) {
			t.Fatalf("index %s columns = %v, want %v", want.name, columns, want.columns)
		}
	}
}

func TestTestRun_PermanentReportIDNullableUnique(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "test_run")

	if info["permanent_report_id"].NotNull {
		t.Fatal("permanent_report_id must be nullable")
	}

	createTestRun(t, db, "run-perm-1")
	createTestRun(t, db, "run-perm-2")
	createTestRun(t, db, "run-perm-3")

	mustExec(t, db, "UPDATE test_run SET permanent_report_id = 'report-1' WHERE test_run_id = 'run-perm-1'")

	if err := db.Exec(
		"UPDATE test_run SET permanent_report_id = 'report-1' WHERE test_run_id = 'run-perm-2'",
	).Error; err == nil {
		t.Fatal("duplicate permanent_report_id must be rejected")
	}

	// NULL values must not collide under the unique constraint.
	mustExec(t, db, "UPDATE test_run SET permanent_report_id = NULL WHERE test_run_id = 'run-perm-3'")
}

func TestTestRun_OptInDefaults(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)
	info := tableInfo(t, db, "test_run")

	for _, col := range []string{"opt_in_stats", "opt_in_permanent"} {
		if !info[col].NotNull {
			t.Fatalf("%s must be NOT NULL", col)
		}

		if info[col].DfltValue == nil || *info[col].DfltValue != "0" {
			t.Fatalf("%s must default to 0, got %+v", col, info[col])
		}
	}

	mustExec(t, db, `INSERT INTO test_run
		(test_run_id, is_active, state, target_origin, target_host, discovery_url, jwks_uri,
		 manifest_schema, session_kind, created_at, updated_at)
		VALUES ('run-defaults', FALSE, 'created', 'https://t.example', 't.example',
		 'https://t.example/.well-known/ocm', 'https://t.example/jwks.json',
		 'ocm-validator-manifest/v1', 'passive_only', 1, 1)`)

	var optInStats, optInPermanent bool

	row := db.Raw(
		"SELECT opt_in_stats, opt_in_permanent FROM test_run WHERE test_run_id = 'run-defaults'",
	).Row()
	if err := row.Scan(&optInStats, &optInPermanent); err != nil {
		t.Fatalf("read opt-in defaults: %v", err)
	}

	if optInStats || optInPermanent {
		t.Fatal("opt-in columns must default to 0 when omitted from the insert")
	}
}

func TestTestRun_StatsHealIndexPredicate(t *testing.T) {
	t.Parallel()

	db := attachFresh(t)

	var indexSQL string

	if err := db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_test_run_stats_heal'",
	).Scan(&indexSQL).Error; err != nil {
		t.Fatalf("read stats heal index: %v", err)
	}

	if indexSQL == "" {
		t.Fatal("idx_test_run_stats_heal index missing")
	}

	if !strings.Contains(indexSQL, "opt_in_stats = 1") ||
		!strings.Contains(indexSQL, "stats_written_at IS NULL") {
		t.Fatalf("stats heal index must be partial on opted-in unwritten runs: %s", indexSQL)
	}
}
