// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"sync"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

type kickCounter interface {
	kickCount() int
}

func (r *recordKicker) kickCount() int {
	if r == nil {
		return 0
	}

	return r.calls
}

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
