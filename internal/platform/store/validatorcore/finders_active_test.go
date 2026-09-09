// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestFinders_InvalidLocalIdentityDoesNotQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		identity     string
		unconfigured bool
	}{
		{name: "empty", identity: ""},
		{name: "unknown", identity: "c"},
		{name: "uppercase a", identity: "A"},
		{name: "unconfigured empty", identity: "", unconfigured: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()
			count := attachQueryCounter(core)

			if tt.unconfigured {
				core = &Core{}
			}

			before := count.Load()

			if _, err := core.FindActiveCorrelation(
				ctx,
				RoleOutgoingToTarget,
				"peer.example",
				"token-1",
				tt.identity,
			); !errors.Is(err, ErrInvalidLocalIdentity) {
				t.Fatalf("FindActiveCorrelation: %v, want ErrInvalidLocalIdentity", err)
			}

			if _, err := core.FindCorrelationAnyStatus(
				ctx,
				RoleOutgoingToTarget,
				"peer.example",
				"token-1",
				tt.identity,
			); !errors.Is(err, ErrInvalidLocalIdentity) {
				t.Fatalf("FindCorrelationAnyStatus: %v, want ErrInvalidLocalIdentity", err)
			}

			if got := count.Load() - before; got != 0 {
				t.Fatalf("queries = %d, want 0", got)
			}
		})
	}
}

func TestFinders_QueryCounterObservesFindActiveByTarget(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	count := attachQueryCounter(core)
	seedActiveRun(t, core, "run-query-probe", "peer.example", true)

	beforeProbe := count.Load()

	if _, err := core.FindActiveByTarget(ctx, "peer.example"); err != nil {
		t.Fatalf("FindActiveByTarget probe: %v", err)
	}

	if count.Load() == beforeProbe {
		t.Fatal("query counter did not observe FindActiveByTarget")
	}
}

func TestFindActiveByTarget_EmptyHostDoesNotQuery(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	count := attachQueryCounter(core)
	before := count.Load()

	if _, err := core.FindActiveByTarget(ctx, ""); err == nil ||
		err.Error() != "validatorcore: empty target host" {
		t.Fatalf("FindActiveByTarget empty host: %v, want empty target host", err)
	}

	if count.Load() != before {
		t.Fatal("empty target host must not query")
	}

	if _, err := (&Core{}).FindActiveByTarget(ctx, ""); err == nil ||
		err.Error() != "validatorcore: empty target host" {
		t.Fatalf("unconfigured empty host: %v, want empty target host", err)
	}
}

func TestFindActiveByTarget_BindsPerTarget(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	runID := "run-one-active"
	host := "peer.example"

	seedActiveRun(t, core, runID, host, true)

	got, err := core.FindActiveByTarget(ctx, host)
	if err != nil {
		t.Fatalf("FindActiveByTarget: %v", err)
	}

	if got != runID {
		t.Fatalf("FindActiveByTarget = %q, want %q", got, runID)
	}

	if _, otherErr := core.FindActiveByTarget(ctx, "other.example"); !errors.Is(otherErr, gorm.ErrRecordNotFound) {
		t.Fatalf("FindActiveByTarget other host = %v, want ErrRecordNotFound", otherErr)
	}

	bobUserID := "bob-user-1"
	if updateErr := core.DB().WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ?", runID).
		Update("bob_user_id", bobUserID).Error; updateErr != nil {
		t.Fatalf("set bob_user_id: %v", updateErr)
	}

	gotAfter, err := core.FindActiveByTarget(ctx, host)
	if err != nil {
		t.Fatalf("FindActiveByTarget after bob_user_id: %v", err)
	}

	if gotAfter != runID {
		t.Fatalf("FindActiveByTarget after bob_user_id = %q, want %q", gotAfter, runID)
	}

	otherID := "run-other-active"
	seedActiveRun(t, core, otherID, "other.example", true)

	gotOther, err := core.FindActiveByTarget(ctx, "other.example")
	if err != nil {
		t.Fatalf("FindActiveByTarget other: %v", err)
	}

	if gotOther != otherID {
		t.Fatalf("FindActiveByTarget other = %q, want %q", gotOther, otherID)
	}

	gotSame, err := core.FindActiveByTarget(ctx, host)
	if err != nil {
		t.Fatalf("FindActiveByTarget original after second host: %v", err)
	}

	if gotSame != runID {
		t.Fatalf("FindActiveByTarget original = %q, want %q", gotSame, runID)
	}

	rows, err := core.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}

	if len(rows) != 2 {
		t.Fatalf("ListActive count = %d, want 2", len(rows))
	}
}

func TestListActive_EmptyAndUpdatedAtOrder(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	rows, err := core.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive empty: %v", err)
	}

	if len(rows) != 0 {
		t.Fatalf("ListActive empty count = %d, want 0", len(rows))
	}

	seedActiveRun(t, core, "run-newer", "newer.example", true)
	seedActiveRun(t, core, "run-older", "older.example", true)

	if ageNewerErr := core.DB().WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ?", "run-newer").
		Update("updated_at", 20).Error; ageNewerErr != nil {
		t.Fatalf("age newer run: %v", ageNewerErr)
	}

	if ageOlderErr := core.DB().WithContext(ctx).Model(&TestRun{}).
		Where("test_run_id = ?", "run-older").
		Update("updated_at", 10).Error; ageOlderErr != nil {
		t.Fatalf("age older run: %v", ageOlderErr)
	}

	ordered, err := core.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}

	if len(ordered) != 2 {
		t.Fatalf("ListActive count = %d, want 2", len(ordered))
	}

	if ordered[0].TestRunID != "run-older" || ordered[1].TestRunID != "run-newer" {
		t.Fatalf(
			"ListActive order = %q, %q, want run-older then run-newer",
			ordered[0].TestRunID,
			ordered[1].TestRunID,
		)
	}
}

func TestFindActiveByTarget_InactiveAndMissingNotFound(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	if _, err := core.FindActiveByTarget(ctx, "peer.example"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("missing active run: %v, want ErrRecordNotFound", err)
	}

	seedActiveRun(t, core, "run-inactive", "peer.example", false)

	if _, err := core.FindActiveByTarget(ctx, "peer.example"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("inactive run: %v, want ErrRecordNotFound", err)
	}
}

func attachQueryCounter(core *Core) *atomic.Int64 {
	count := &atomic.Int64{}
	queryLogger := &queryCountLogger{count: count}
	db := core.DB()
	db.Logger = queryLogger

	return count
}

type queryCountLogger struct {
	count *atomic.Int64
}

func (l *queryCountLogger) LogMode(logger.LogLevel) logger.Interface {
	return l
}

func (l *queryCountLogger) Info(context.Context, string, ...any) {}

func (l *queryCountLogger) Warn(context.Context, string, ...any) {}

func (l *queryCountLogger) Error(context.Context, string, ...any) {}

func (l *queryCountLogger) Trace(
	_ context.Context,
	_ time.Time,
	_ func() (sql string, rowsAffected int64),
	_ error,
) {
	l.count.Add(1)
}
