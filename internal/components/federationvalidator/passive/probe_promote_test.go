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
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestStartupPromote_SameFollowUpAsProbe(t *testing.T) {
	t.Parallel()

	t.Run("startup promote then bind", func(t *testing.T) {
		t.Parallel()

		store := openHandlerTestStore(t)
		ctx := t.Context()
		runID := "run-startup-follow"

		seedReadyWaiter(t, store, runID, time.Now().Unix())

		if err := store.PromoteOldestReadyWaiter(ctx); err != nil {
			t.Fatalf("PromoteOldestReadyWaiter: %v", err)
		}

		kicker := &recordKicker{}
		parties := identity.NewMemoryPartyRepo()
		h := NewHandlerWithDeps(ProbeDeps{Store: store, ActiveKick: kicker})
		allowActiveExtend(h)
		h.SetReverseReceiver(
			parties,
			"local.example",
			config.DefaultValidatorProbeEmail,
			config.DefaultValidatorProbeDisplayName,
		)

		assertPromotedFollowUp(
			t,
			store,
			parties,
			kicker,
			runID,
			1,
		)
	})

	t.Run("probe promote", func(t *testing.T) {
		t.Parallel()

		store := openHandlerTestStore(t)
		kicker := &recordKicker{}
		parties := identity.NewMemoryPartyRepo()
		h := NewHandlerWithDeps(ProbeDeps{Store: store, ActiveKick: kicker})
		allowActiveExtend(h)
		h.SetReverseReceiver(
			parties,
			"local.example",
			config.DefaultValidatorProbeEmail,
			config.DefaultValidatorProbeDisplayName,
		)

		runID := "run-probe-follow"
		createCreatedRun(t, store, runID, "https://peer.example", true, false)
		h.probe.run(t.Context(), runID)

		assertPromotedFollowUp(
			t,
			store,
			parties,
			kicker,
			runID,
			1,
		)
	})

	t.Run("concurrent stop still promotes survivor", func(t *testing.T) {
		t.Parallel()

		store := openHandlerTestStore(t)
		ctx := t.Context()
		now := time.Now().Unix()

		seedReadyWaiter(t, store, "run-startup-old", now-20)
		seedReadyWaiter(t, store, "run-startup-new", now-5)
		store.SetPromoteAfterSelectHook(func(id string) {
			store.SetPromoteAfterSelectHook(nil)

			if id != "run-startup-old" {
				t.Fatalf("selected waiter = %q, want run-startup-old", id)
			}

			if err := store.StopPassive(ctx, id); err != nil {
				t.Fatalf("StopPassive: %v", err)
			}
		})

		if err := store.PromoteOldestReadyWaiter(ctx); err != nil {
			t.Fatalf("PromoteOldestReadyWaiter: %v", err)
		}

		kicker := &recordKicker{}
		parties := identity.NewMemoryPartyRepo()
		h := NewHandlerWithDeps(ProbeDeps{Store: store, ActiveKick: kicker})
		allowActiveExtend(h)
		h.SetReverseReceiver(
			parties,
			"local.example",
			config.DefaultValidatorProbeEmail,
			config.DefaultValidatorProbeDisplayName,
		)

		old, err := store.GetTestRun(ctx, "run-startup-old")
		if err != nil {
			t.Fatalf("GetTestRun old: %v", err)
		}

		if old.State != validatorcore.StateTerminalFail {
			t.Fatalf("old state = %q, want terminal_fail", old.State)
		}

		assertPromotedFollowUp(
			t,
			store,
			parties,
			kicker,
			"run-startup-new",
			1,
		)
	})
}

func TestStartupPromote_LateBindDeliversOnce(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	ctx := t.Context()
	firstID := "run-late-first"

	seedReadyWaiter(t, store, firstID, time.Now().Unix())
	mustPromoteOldest(t, store)
	assertLastPromotedID(t, store, firstID)

	follow := &orderedFollowUp{}
	parties := &createLogRepo{
		PartyRepo: identity.NewMemoryPartyRepo(),
		log:       follow,
	}
	h := NewHandlerWithDeps(ProbeDeps{Store: store, ActiveKick: follow})
	allowActiveExtend(h)

	assertNoFollowUpYet(t, follow, parties)

	h.SetReverseReceiver(
		parties,
		"local.example",
		config.DefaultValidatorProbeEmail,
		config.DefaultValidatorProbeDisplayName,
	)

	assertPromotedFollowUp(
		t,
		store,
		parties,
		follow,
		firstID,
		1,
	)
	assertFollowUpOrder(t, follow, "bob", "kick")
	assertLastPromotedID(t, store, "")

	store.FlushPromoteFollowUp(ctx)

	assertKickCount(t, follow, 1)

	mustReleaseActive(t, store, firstID)

	secondID := "run-late-second"
	seedReadyWaiter(t, store, secondID, time.Now().Unix())
	mustPromoteOldest(t, store)

	assertPromotedFollowUp(
		t,
		store,
		parties,
		follow,
		secondID,
		2,
	)
	assertFollowUpOrder(t, follow, "bob", "kick", "bob", "kick")
	assertLastPromotedID(t, store, "")
	assertFirstBobKept(t, store, parties, firstID)

	store.FlushPromoteFollowUp(ctx)
	mustPromoteOldest(t, store)

	assertKickCount(t, follow, 2)
}

func TestPromoteFollowUp_MaterializeErrorDefersKick(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	ctx := t.Context()
	runID := "run-materialize-fail"
	follow := &orderedFollowUp{}
	parties := newFailThenCreateRepo(identity.NewMemoryPartyRepo(), follow, 1)
	h := NewHandlerWithDeps(ProbeDeps{Store: store, ActiveKick: follow})
	allowActiveExtend(h)

	h.SetReverseReceiver(
		parties,
		"local.example",
		config.DefaultValidatorProbeEmail,
		config.DefaultValidatorProbeDisplayName,
	)

	seedReadyWaiter(t, store, runID, time.Now().Unix())
	mustPromoteOldest(t, store)

	assertKickCount(t, follow, 0)
	assertLastPromotedID(t, store, runID)
	assertNoBobParty(t, parties)

	store.FlushPromoteFollowUp(ctx)

	assertPromotedFollowUp(t, store, parties, follow, runID, 1)
	assertFollowUpOrder(t, follow, "bob", "kick")
	assertLastPromotedID(t, store, "")

	store.FlushPromoteFollowUp(ctx)
	assertKickCount(t, follow, 1)
}

func TestPromoteFollowUp_ConcurrentIdempotentExactlyOnce(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	ctx := t.Context()
	runID := "run-idempotent-once"
	follow := &orderedFollowUp{}
	parties := &createLogRepo{
		PartyRepo: identity.NewMemoryPartyRepo(),
		log:       follow,
	}
	h := NewHandlerWithDeps(ProbeDeps{Store: store, ActiveKick: follow})
	allowActiveExtend(h)
	h.SetReverseReceiver(
		parties,
		"local.example",
		config.DefaultValidatorProbeEmail,
		config.DefaultValidatorProbeDisplayName,
	)

	seedReadyWaiter(t, store, runID, time.Now().Unix())

	var wg sync.WaitGroup

	start := make(chan struct{})
	errs := make(chan error, 2)

	for range 2 {
		wg.Go(func() {
			<-start

			errs <- h.probe.promoteOrWait(ctx, runID)
		})
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("promoteOrWait: %v", err)
		}
	}

	assertPromotedFollowUp(t, store, parties, follow, runID, 1)
	assertFollowUpOrder(t, follow, "bob", "kick")
	assertLastPromotedID(t, store, "")
}

func TestPromoteFollowUp_ConcurrentStartupProbeLateBind(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	ctx := t.Context()
	runID := "run-triple-race"
	follow := &orderedFollowUp{}
	parties := &createLogRepo{
		PartyRepo: identity.NewMemoryPartyRepo(),
		log:       follow,
	}
	h := NewHandlerWithDeps(ProbeDeps{Store: store, ActiveKick: follow})
	allowActiveExtend(h)

	seedReadyWaiter(t, store, runID, time.Now().Unix())

	var wg sync.WaitGroup

	start := make(chan struct{})
	errs := make(chan error, 2)

	wg.Go(func() {
		<-start

		errs <- store.PromoteOldestReadyWaiter(ctx)
	})
	wg.Go(func() {
		<-start

		errs <- h.probe.promoteOrWait(ctx, runID)
	})
	wg.Go(func() {
		<-start

		h.SetReverseReceiver(
			parties,
			"local.example",
			config.DefaultValidatorProbeEmail,
			config.DefaultValidatorProbeDisplayName,
		)
	})

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent promote: %v", err)
		}
	}

	assertPromotedFollowUp(t, store, parties, follow, runID, 1)
	assertFollowUpOrder(t, follow, "bob", "kick")
	assertLastPromotedID(t, store, "")
}

func TestPromoteOrWait_NilCanExtendDoesNotPromote(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	runID := "run-nil-extend"
	readyAt := time.Now().Unix()

	seedReadyWaiter(t, store, runID, readyAt)

	if err := h.probe.promoteOrWait(t.Context(), runID); err != nil {
		t.Fatalf("promoteOrWait: %v", err)
	}

	got, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive || got.State != validatorcore.StatePassiveRunning {
		t.Fatalf("nil canExtend promoted session: is_active=%v state=%q", got.IsActive, got.State)
	}
}

func TestPromoteOrWait_FalseCanExtendDoesNotPromote(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)
	h.SetCaps(catalog.Caps{})

	runID := "run-false-extend"
	readyAt := time.Now().Unix()

	seedReadyWaiter(t, store, runID, readyAt)

	if err := h.probe.promoteOrWait(t.Context(), runID); err != nil {
		t.Fatalf("promoteOrWait: %v", err)
	}

	got, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.IsActive || got.State != validatorcore.StatePassiveRunning {
		t.Fatalf("false canExtend promoted session: is_active=%v state=%q", got.IsActive, got.State)
	}
}

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

type kickCounter interface {
	kickCount() int
}

func (r *recordKicker) kickCount() int {
	if r == nil {
		return 0
	}

	return r.calls
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
