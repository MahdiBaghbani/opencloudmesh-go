// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func seedReadyWaiter(t *testing.T, store *validatorcore.Core, runID string, readyAt int64) {
	t.Helper()

	row := &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StatePassiveRunning,
		TargetHost:     "waiter.example",
		OptInActive:    true,
		PassiveReadyAt: &readyAt,
		CreatedAt:      readyAt,
		UpdatedAt:      readyAt,
	}

	if err := store.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed ready waiter %s: %v", runID, err)
	}
}

type orderedFollowUp struct {
	mu     sync.Mutex
	events []string
	kicks  int
}

func (o *orderedFollowUp) Kick() {
	if o == nil {
		return
	}

	o.record("kick")
}

func (o *orderedFollowUp) record(event string) {
	if o == nil {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	o.events = append(o.events, event)
	if event == "kick" {
		o.kicks++
	}
}

func (o *orderedFollowUp) kickCount() int {
	if o == nil {
		return 0
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	return o.kicks
}

func (o *orderedFollowUp) snapshot() []string {
	if o == nil {
		return nil
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	return append([]string{}, o.events...)
}

type createLogRepo struct {
	identity.PartyRepo

	log *orderedFollowUp
}

func (r *createLogRepo) Create(ctx context.Context, user *identity.User) error {
	if err := r.PartyRepo.Create(ctx, user); err != nil {
		return fmt.Errorf("create logged party: %w", err)
	}

	if r.log != nil {
		r.log.record("bob")
	}

	return nil
}

type failThenCreateRepo struct {
	identity.PartyRepo

	log      *orderedFollowUp
	failLeft atomic.Int64
}

func newFailThenCreateRepo(
	inner identity.PartyRepo,
	log *orderedFollowUp,
	failCount int64,
) *failThenCreateRepo {
	repo := &failThenCreateRepo{
		PartyRepo: inner,
		log:       log,
	}
	repo.failLeft.Store(failCount)

	return repo
}

func (r *failThenCreateRepo) Create(ctx context.Context, user *identity.User) error {
	if r.failLeft.Add(-1) >= 0 {
		return errors.New("reverse receiver create failed")
	}

	if err := r.PartyRepo.Create(ctx, user); err != nil {
		return fmt.Errorf("create logged party: %w", err)
	}

	if r.log != nil {
		r.log.record("bob")
	}

	return nil
}

func mustPromoteOldest(t *testing.T, store *validatorcore.Core) {
	t.Helper()

	if err := store.PromoteOldestReadyWaiter(t.Context()); err != nil {
		t.Fatalf("PromoteOldestReadyWaiter: %v", err)
	}
}

func mustReleaseActive(t *testing.T, store *validatorcore.Core, runID string) {
	t.Helper()

	err := store.ReleaseActiveHardFail(
		t.Context(),
		runID,
		validatorcore.ReasonOperatorAborted,
	)
	if err != nil {
		t.Fatalf("ReleaseActiveHardFail: %v", err)
	}
}

func assertPromotedFollowUp(
	t *testing.T,
	store *validatorcore.Core,
	parties identity.PartyRepo,
	kicker kickCounter,
	runID string,
	wantKicks int,
) {
	t.Helper()

	run, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !run.IsActive || run.State != validatorcore.StateActiveRunning {
		t.Fatalf("is_active=%v state=%q, want active_running", run.IsActive, run.State)
	}

	if run.BobUserID == nil || *run.BobUserID == "" {
		t.Fatal("bob_user_id is empty after promotion")
	}

	bob, err := parties.Get(t.Context(), *run.BobUserID)
	if err != nil {
		t.Fatalf("Get bob party: %v", err)
	}

	if bob.ID != *run.BobUserID {
		t.Fatalf("bob id = %q, want %q", bob.ID, *run.BobUserID)
	}

	if kicker.kickCount() != wantKicks {
		t.Fatalf("Kick calls = %d, want %d", kicker.kickCount(), wantKicks)
	}
}

func assertLastPromotedID(t *testing.T, store *validatorcore.Core, want string) {
	t.Helper()

	if got := store.LastPromotedID(); got != want {
		t.Fatalf("LastPromotedID = %q, want %q", got, want)
	}
}

func assertKickCount(t *testing.T, follow *orderedFollowUp, want int) {
	t.Helper()

	if follow.kickCount() != want {
		t.Fatalf("Kick calls = %d, want %d", follow.kickCount(), want)
	}
}

func assertNoBobParty(t *testing.T, parties identity.PartyRepo) {
	t.Helper()

	listed, listErr := parties.List(t.Context(), "")
	if listErr != nil {
		t.Fatalf("List parties: %v", listErr)
	}

	if len(listed) != 0 {
		t.Fatalf("Bob materialized after failed create: %d parties", len(listed))
	}
}

func assertNoFollowUpYet(t *testing.T, follow *orderedFollowUp, parties identity.PartyRepo) {
	t.Helper()

	assertKickCount(t, follow, 0)

	listed, listErr := parties.List(t.Context(), "")
	if listErr != nil {
		t.Fatalf("List parties: %v", listErr)
	}

	if len(listed) != 0 {
		t.Fatalf("Bob materialized before SetReverseReceiver: %d parties", len(listed))
	}
}

func assertFirstBobKept(
	t *testing.T,
	store *validatorcore.Core,
	parties identity.PartyRepo,
	runID string,
) {
	t.Helper()

	first, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun first: %v", err)
	}

	if _, getErr := parties.Get(t.Context(), *first.BobUserID); getErr != nil {
		t.Fatalf("first Bob replayed away: %v", getErr)
	}
}

func assertFollowUpOrder(t *testing.T, follow *orderedFollowUp, want ...string) {
	t.Helper()

	if follow == nil {
		t.Fatal("follow-up log is nil")
	}

	got := follow.snapshot()
	if len(got) != len(want) {
		t.Fatalf("follow-up events = %v, want %v", got, want)
	}

	for i, event := range want {
		if got[i] != event {
			t.Fatalf("follow-up events = %v, want %v", got, want)
		}
	}
}
