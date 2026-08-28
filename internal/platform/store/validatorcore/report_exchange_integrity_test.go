// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"sync"
	"testing"

	"gorm.io/gorm"
)

func TestInsertReportExchange_RejectsDuplicateSeq(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-seq-unique"
	createTestRun(t, core.DB(), runID)

	first := newMinimalExchange(runID)
	if err := core.InsertReportExchange(ctx, first); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	dup := newMinimalExchange(runID)
	dup.Seq = first.Seq

	err := core.InsertReportExchange(ctx, dup)
	requireReportExchangeStoreError(t, err, gorm.ErrDuplicatedKey)

	if dup.Seq != first.Seq {
		t.Fatalf("explicit duplicate seq = %d, want unchanged %d", dup.Seq, first.Seq)
	}

	if countReportExchanges(t, core, runID) != 1 {
		t.Fatal("duplicate seq insert must not add a row")
	}
}

func TestInsertReportExchange_RejectsDuplicateRequestID(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-idem"
	createTestRun(t, core.DB(), runID)

	reqID := "req-same"
	first := newMinimalExchange(runID)
	first.RequestID = &reqID

	if err := core.InsertReportExchange(ctx, first); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	dup := newMinimalExchange(runID)
	dup.RequestID = &reqID

	err := core.InsertReportExchange(ctx, dup)
	requireReportExchangeStoreError(t, err, gorm.ErrDuplicatedKey)

	if dup.Seq != 0 {
		t.Fatalf("failed idempotent row seq = %d, want 0 after rollback", dup.Seq)
	}

	if countReportExchanges(t, core, runID) != 1 {
		t.Fatal("idempotent retry must not insert a second row")
	}

	nextReq := "req-after-dup"
	dup.RequestID = &nextReq

	if insertErr := core.InsertReportExchange(ctx, dup); insertErr != nil {
		t.Fatalf("retry after idempotency failure: %v", insertErr)
	}

	if dup.Seq != 2 {
		t.Fatalf("seq after idempotency retry = %d, want 2", dup.Seq)
	}
}

func TestInsertReportExchange_AllowsNullAndEmptyRequestID(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-req-null"
	createTestRun(t, core.DB(), runID)

	empty := ""

	for _, row := range []*ReportExchange{
		newMinimalExchange(runID),
		newMinimalExchange(runID),
		func() *ReportExchange {
			row := newMinimalExchange(runID)
			row.RequestID = &empty

			return row
		}(),
		func() *ReportExchange {
			row := newMinimalExchange(runID)
			row.RequestID = &empty

			return row
		}(),
	} {
		if err := core.InsertReportExchange(ctx, row); err != nil {
			t.Fatalf("insert nullable request_id: %v", err)
		}
	}

	if countReportExchanges(t, core, runID) != 4 {
		t.Fatalf("rows = %d, want 4", countReportExchanges(t, core, runID))
	}

	reqID := "shared"
	inRow := newMinimalExchange(runID)
	inRow.Direction = "in"
	inRow.RequestID = &reqID

	outRow := newMinimalExchange(runID)
	outRow.RequestID = &reqID

	if err := core.InsertReportExchange(ctx, inRow); err != nil {
		t.Fatalf("insert other direction: %v", err)
	}

	if err := core.InsertReportExchange(ctx, outRow); err != nil {
		t.Fatalf("same request_id on a different direction must be accepted: %v", err)
	}
}

func TestInsertReportExchange_OrphanFKAndRollback(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-fk-rollback"
	createTestRun(t, core.DB(), runID)

	orphan := newMinimalExchange("missing")
	err := core.InsertReportExchange(ctx, orphan)
	requireReportExchangeStoreError(t, err, gorm.ErrForeignKeyViolated)

	if orphan.Seq != 0 {
		t.Fatalf("failed orphan row seq = %d, want 0 after rollback", orphan.Seq)
	}

	if countReportExchanges(t, core, allTestRunIDs) != 0 {
		t.Fatal("failed orphan insert must leave no report_exchange rows")
	}

	valid := newMinimalExchange(runID)
	missing := newMinimalExchange("missing")

	err = core.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if insertErr := insertReportExchangeDB(tx, valid); insertErr != nil {
			return insertErr
		}

		return insertReportExchangeDB(tx, missing)
	})
	requireReportExchangeStoreError(t, err, gorm.ErrForeignKeyViolated)

	if missing.Seq != 0 {
		t.Fatalf("failed transaction row seq = %d, want 0 after rollback", missing.Seq)
	}

	if countReportExchanges(t, core, runID) != 0 {
		t.Fatal("FK failure must roll back the earlier valid insert")
	}

	orphan.TestRunID = runID
	if retryErr := core.InsertReportExchange(ctx, orphan); retryErr != nil {
		t.Fatalf("retry after FK failure: %v", retryErr)
	}

	if orphan.Seq != 1 {
		t.Fatalf("seq after FK retry = %d, want 1", orphan.Seq)
	}
}

func TestInsertReportExchange_RejectsParentDeleteWithChild(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-parent-delete"
	createTestRun(t, core.DB(), runID)

	row := newMinimalExchange(runID)
	if err := core.InsertReportExchange(ctx, row); err != nil {
		t.Fatalf("valid insert: %v", err)
	}

	if countReportExchanges(t, core, runID) != 1 {
		t.Fatal("valid child insert must persist one row")
	}

	conn1, conn2 := acquireTwoSQLConns(t, core)

	_, err1 := conn1.ExecContext(ctx, "DELETE FROM test_run WHERE test_run_id = ?", runID)
	_, err2 := conn2.ExecContext(ctx, "DELETE FROM test_run WHERE test_run_id = ?", runID)

	requireSQLiteParentRestrictError(t, err1)
	requireSQLiteParentRestrictError(t, err2)

	var runs, exchanges int64
	if scanErr := conn1.QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM test_run WHERE test_run_id = ?",
		runID,
	).Scan(&runs); scanErr != nil {
		t.Fatalf("count test_run: %v", scanErr)
	}

	if runs != 1 {
		t.Fatal("failed parent delete must leave the test_run")
	}

	if scanErr := conn1.QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM report_exchange WHERE test_run_id = ?",
		runID,
	).Scan(&exchanges); scanErr != nil {
		t.Fatalf("count report_exchange: %v", scanErr)
	}

	if exchanges != 1 {
		t.Fatal("failed parent delete must leave the report_exchange child")
	}
}

func TestInsertReportExchange_ConcurrentSeq(t *testing.T) {
	t.Parallel()

	core := openMigratedProductionCore(t)
	ctx := t.Context()
	runID := "run-concurrent-seq"
	createTestRun(t, core.DB(), runID)

	const workers = 8

	var wg sync.WaitGroup

	errCh := make(chan error, workers)

	for range workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			errCh <- core.InsertReportExchange(ctx, newMinimalExchange(runID))
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent insert: %v", err)
		}
	}

	var seqs []int
	if err := core.DB().WithContext(ctx).
		Model(&ReportExchange{}).
		Where("test_run_id = ?", runID).
		Pluck("seq", &seqs).Error; err != nil {
		t.Fatalf("pluck seq: %v", err)
	}

	if len(seqs) != workers {
		t.Fatalf("rows = %d, want %d", len(seqs), workers)
	}

	seen := make(map[int]struct{}, workers)

	for _, seq := range seqs {
		if seq < 1 || seq > workers {
			t.Fatalf("seq %d out of range 1..%d", seq, workers)
		}

		if _, ok := seen[seq]; ok {
			t.Fatalf("duplicate allocated seq %d", seq)
		}

		seen[seq] = struct{}{}
	}
}

func requireReportExchangeStoreError(t *testing.T, err, want error) {
	t.Helper()

	if err == nil {
		t.Fatal("expected report exchange store error")
	}

	var storeErr *StoreError
	if !errors.As(err, &storeErr) || storeErr.Op != OpInsertReportExchange {
		t.Fatalf("error = %v, want StoreError op %s", err, OpInsertReportExchange)
	}

	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}
