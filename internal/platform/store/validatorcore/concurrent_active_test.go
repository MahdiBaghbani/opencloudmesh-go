// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestConcurrentActive_DifferentTargetsProgress(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	seedPassiveOn(t, core, "run-alpha", "alpha.example")
	seedPassiveOn(t, core, "run-beta", "beta.example")

	var wg sync.WaitGroup

	start := make(chan struct{})
	errs := make(chan error, 2)

	wg.Add(2)

	for _, id := range []string{"run-alpha", "run-beta"} {
		go func(runID string) {
			defer wg.Done()

			<-start

			errs <- core.ExtendToActive(ctx, runID)
		}(id)
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("ExtendToActive: %v", err)
		}
	}

	gotAlpha, err := core.FindActiveByTarget(ctx, "alpha.example")
	if err != nil {
		t.Fatalf("FindActiveByTarget alpha: %v", err)
	}

	gotBeta, err := core.FindActiveByTarget(ctx, "beta.example")
	if err != nil {
		t.Fatalf("FindActiveByTarget beta: %v", err)
	}

	if gotAlpha != "run-alpha" || gotBeta != "run-beta" {
		t.Fatalf("active ids = %q, %q, want run-alpha and run-beta", gotAlpha, gotBeta)
	}

	rows, err := core.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}

	if len(rows) != 2 {
		t.Fatalf("ListActive count = %d, want 2", len(rows))
	}
}

func TestConcurrentActive_SameTargetExcluded(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)

	seedPassiveOn(t, core, "run-first", "lock.example")
	seedPassiveOn(t, core, "run-second", "lock.example")
	requireOneWinOneBusy(t, raceExtendToActive(t, core, "run-first", "run-second"))
	requireOneActiveOnHost(t, core, "lock.example", "run-first", "run-second")
	requireDirectActiveInsertRejected(t, core, "lock.example")

	if _, missErr := core.FindActiveByTarget(t.Context(), "missing.example"); !errors.Is(missErr, gorm.ErrRecordNotFound) {
		t.Fatalf("missing host = %v, want ErrRecordNotFound", missErr)
	}
}

func raceExtendToActive(t *testing.T, core *Core, ids ...string) []error {
	t.Helper()

	ctx := t.Context()

	var wg sync.WaitGroup

	start := make(chan struct{})
	errs := make(chan error, len(ids))
	out := make([]error, 0, len(ids))

	wg.Add(len(ids))

	for _, id := range ids {
		go func(runID string) {
			defer wg.Done()

			<-start

			errs <- core.ExtendToActive(ctx, runID)
		}(id)
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		out = append(out, err)
	}

	return out
}

func requireOneWinOneBusy(t *testing.T, errs []error) {
	t.Helper()

	var (
		wins  int
		busy  int
		other []error
	)

	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case IsTargetSlotBusy(err):
			busy++
		default:
			other = append(other, err)
		}
	}

	if wins != 1 || busy != 1 || len(other) != 0 {
		t.Fatalf("wins=%d busy=%d other=%v, want 1 win and 1 IsTargetSlotBusy", wins, busy, other)
	}
}

func requireOneActiveOnHost(t *testing.T, core *Core, host string, wantIDs ...string) {
	t.Helper()

	got, err := core.FindActiveByTarget(t.Context(), host)
	if err != nil {
		t.Fatalf("FindActiveByTarget: %v", err)
	}

	if !slices.Contains(wantIDs, got) {
		t.Fatalf("active id = %q, want one of %v", got, wantIDs)
	}

	rows, err := core.ListActive(t.Context())
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}

	if len(rows) != 1 {
		t.Fatalf("ListActive count = %d, want 1", len(rows))
	}
}

func requireDirectActiveInsertRejected(t *testing.T, core *Core, host string) {
	t.Helper()

	rejected := core.DB().WithContext(t.Context()).Create(&TestRun{
		TestRunID:  "run-direct-reject",
		IsActive:   true,
		State:      StateActiveRunning,
		TargetHost: host,
		CreatedAt:  1,
		UpdatedAt:  1,
	}).Error
	if !errors.Is(rejected, gorm.ErrDuplicatedKey) {
		t.Fatalf("second active insert = %v, want ErrDuplicatedKey", rejected)
	}
}

func TestConcurrentActive_PromoteDifferentTargets(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()

	seedReadyWaiterOn(t, core, "run-promote-a", "alpha.example", now-20)
	seedReadyWaiterOn(t, core, "run-promote-b", "beta.example", now-10)

	var wg sync.WaitGroup

	start := make(chan struct{})
	errs := make(chan error, 2)

	wg.Add(2)

	go func() {
		defer wg.Done()

		<-start

		errs <- core.PromoteOldestReadyWaiter(ctx, "alpha.example")
	}()
	go func() {
		defer wg.Done()

		<-start

		errs <- core.PromoteOldestReadyWaiter(ctx, "beta.example")
	}()

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("PromoteOldestReadyWaiter: %v", err)
		}
	}

	for _, item := range []struct {
		id   string
		host string
	}{
		{id: "run-promote-a", host: "alpha.example"},
		{id: "run-promote-b", host: "beta.example"},
	} {
		got, err := core.FindActiveByTarget(ctx, item.host)
		if err != nil {
			t.Fatalf("FindActiveByTarget %s: %v", item.host, err)
		}

		if got != item.id {
			t.Fatalf("FindActiveByTarget %s = %q, want %q", item.host, got, item.id)
		}

		row, err := core.GetTestRun(ctx, item.id)
		if err != nil {
			t.Fatalf("GetTestRun %s: %v", item.id, err)
		}

		if !row.IsActive || row.State != StateActiveRunning {
			t.Fatalf("%s is_active=%v state=%q, want active_running", item.id, row.IsActive, row.State)
		}
	}

	rows, err := core.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}

	if len(rows) != 2 {
		t.Fatalf("ListActive count = %d, want 2", len(rows))
	}
}

func TestConcurrentActive_PromoteSameTargetExcluded(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()

	seedReadyWaiterOn(t, core, "run-old", "shared.example", now-20)
	seedReadyWaiterOn(t, core, "run-new", "shared.example", now-5)

	var wg sync.WaitGroup

	start := make(chan struct{})
	errs := make(chan error, 2)

	wg.Add(2)

	for range 2 {
		go func() {
			defer wg.Done()

			<-start

			errs <- core.PromoteOldestReadyWaiter(ctx, "shared.example")
		}()
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("PromoteOldestReadyWaiter: %v", err)
		}
	}

	got, err := core.FindActiveByTarget(ctx, "shared.example")
	if err != nil {
		t.Fatalf("FindActiveByTarget: %v", err)
	}

	if got != "run-old" {
		t.Fatalf("active id = %q, want run-old", got)
	}

	older, err := core.GetTestRun(ctx, "run-old")
	if err != nil {
		t.Fatalf("GetTestRun old: %v", err)
	}

	if !older.IsActive || older.State != StateActiveRunning {
		t.Fatalf("old is_active=%v state=%q, want promoted", older.IsActive, older.State)
	}

	newer, err := core.GetTestRun(ctx, "run-new")
	if err != nil {
		t.Fatalf("GetTestRun new: %v", err)
	}

	if newer.IsActive {
		t.Fatal("newer waiter took the same-target slot")
	}

	rows, err := core.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}

	if len(rows) != 1 {
		t.Fatalf("ListActive count = %d, want 1", len(rows))
	}
}

func seedPassiveOn(t *testing.T, core *Core, runID, host string) {
	t.Helper()

	now := time.Now().Unix()
	row := &TestRun{
		TestRunID:    runID,
		State:        StatePassiveComplete,
		TargetOrigin: "https://" + host,
		TargetHost:   host,
		DiscoveryURL: "https://" + host + "/.well-known/ocm",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := core.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed passive %s: %v", runID, err)
	}
}
