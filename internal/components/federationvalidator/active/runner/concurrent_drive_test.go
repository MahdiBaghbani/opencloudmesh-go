// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package runner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestTryAcquireDrive_BoundsWorkersAtK16(t *testing.T) {
	t.Parallel()

	r := newDriveEnv(t, &driveInvites{}, nil, 0).runner
	if cap(r.drivePermits) != defaultDriveWorkers {
		t.Fatalf("drive permit cap = %d, want %d", cap(r.drivePermits), defaultDriveWorkers)
	}

	for i := range defaultDriveWorkers {
		if !r.tryAcquireDrive() {
			t.Fatalf("permit %d refused", i)
		}
	}

	if r.tryAcquireDrive() {
		t.Fatal("permit 17 acquired, want bound at K=16")
	}

	r.releaseDrive()

	if !r.tryAcquireDrive() {
		t.Fatal("permit after release refused")
	}
}

func TestDriveSessionCycle_WaitStateUsesNoPermit(t *testing.T) {
	t.Parallel()

	env := newDriveEnv(t, &driveInvites{}, nil, 0)
	r := env.runner
	runID := "run-wait-permit"
	seedDriveRun(t, env.store, runID, "wait.example", validatorcore.StateCapabilityExercise)
	h := newCycleHandle(t, r, runID)

	if !r.driveSessionCycle(h) {
		t.Fatal("wait-state cycle exited")
	}

	if len(r.drivePermits) != 0 {
		t.Fatalf("wait-state held %d permits, want 0", len(r.drivePermits))
	}

	if env.invites.mints.Load() != 0 {
		t.Fatalf("wait state minted %d times", env.invites.mints.Load())
	}

	if r.parkDuration(h) <= 0 {
		t.Fatal("parkDuration <= 0 would hot-loop wait states")
	}
}

func TestDriveSessionCycle_FullSemaphoreUsesNoPermit(t *testing.T) {
	t.Parallel()

	env := newDriveEnv(t, &driveInvites{}, nil, 0)
	r := env.runner
	runID := "run-full-sem"
	seedDriveRun(t, env.store, runID, "full.example", validatorcore.StateActiveRunning)
	bindDriveBob(t, env.store, runID)

	for i := range defaultDriveWorkers {
		if !r.tryAcquireDrive() {
			t.Fatalf("preload permit %d refused", i)
		}
	}

	held := len(r.drivePermits)
	if held != defaultDriveWorkers {
		t.Fatalf("preloaded permits = %d, want %d", held, defaultDriveWorkers)
	}

	h := newCycleHandle(t, r, runID)

	if !r.driveSessionCycle(h) {
		t.Fatal("full-semaphore cycle exited")
	}

	if len(r.drivePermits) != held {
		t.Fatalf("held permits after full-semaphore cycle = %d, want %d", len(r.drivePermits), held)
	}

	if r.tryAcquireDrive() {
		t.Fatal("full-semaphore cycle leaked a permit")
	}

	if env.invites.mints.Load() != 0 {
		t.Fatalf("full-semaphore minted %d times", env.invites.mints.Load())
	}
}

func TestDriveOnce_DifferentTargetsProgress(t *testing.T) {
	t.Parallel()

	env := newDriveEnv(t, &driveInvites{}, nil, 0)
	ctx := t.Context()
	seedDriveRun(t, env.store, "run-a", "alpha.example", validatorcore.StateActiveRunning)
	seedDriveRun(t, env.store, "run-b", "beta.example", validatorcore.StateActiveRunning)
	bindDriveBob(t, env.store, "run-a")
	bindDriveBob(t, env.store, "run-b")
	env.runner.DriveOnce(ctx)

	if env.invites.mints.Load() != 2 || env.invites.count("run-a") != 1 || env.invites.count("run-b") != 1 {
		t.Fatalf("mints total=%d a=%d b=%d, want 1 each", env.invites.mints.Load(), env.invites.count("run-a"), env.invites.count("run-b"))
	}

	rows, err := env.store.ListActive(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("ListActive count = %d err=%v, want 2", len(rows), err)
	}
}

func TestSupervisor_DifferentTargetsDriveConcurrently(t *testing.T) {
	t.Parallel()

	invites := &barrierInvites{release: make(chan struct{})}
	invites.arrived.Add(2)
	env := newDriveEnv(t, invites, nil, 0)
	seedDriveRun(t, env.store, "run-a", "alpha.example", validatorcore.StateActiveRunning)
	seedDriveRun(t, env.store, "run-b", "beta.example", validatorcore.StateActiveRunning)
	bindDriveBob(t, env.store, "run-a")
	bindDriveBob(t, env.store, "run-b")
	env.runner.Start()
	t.Cleanup(func() {
		close(invites.release)
		env.runner.Stop()
	})
	invites.arrived.Wait()

	if got := invites.peak.Load(); got != 2 {
		t.Fatalf("different-target peak inflight = %d, want 2", got)
	}

	if got := invites.inflight.Load(); got != 2 {
		t.Fatalf("different-target current inflight = %d, want 2", got)
	}
}

func TestSupervisor_SameTargetSerializesOneHandle(t *testing.T) {
	t.Parallel()

	invites := &barrierInvites{release: make(chan struct{}), maxArrive: 1}
	invites.arrived.Add(1)
	env := newDriveEnv(t, invites, nil, 0)
	runID := "run-same-target"
	seedDriveRun(t, env.store, runID, "same.example", validatorcore.StateActiveRunning)
	bindDriveBob(t, env.store, runID)

	if err := env.store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID:    "run-same-dup",
		IsActive:     true,
		State:        validatorcore.StateActiveRunning,
		TargetOrigin: "https://same.example",
		TargetHost:   "same.example",
		DiscoveryURL: "https://same.example/.well-known/ocm",
		CreatedAt:    1,
		UpdatedAt:    1,
	}).Error; !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("second same-target active insert = %v, want ErrDuplicatedKey", err)
	}

	var wg sync.WaitGroup

	armed := make(chan struct{}, 2)
	start := make(chan struct{})

	wg.Add(2)

	for range 2 {
		go func() {
			defer wg.Done()

			armed <- struct{}{}

			<-start
			env.runner.ensureHandle(runID)
			env.runner.Kick()
		}()
	}

	for range 2 {
		<-armed
	}

	env.runner.Start()
	t.Cleanup(func() {
		close(invites.release)
		env.runner.Stop()
	})
	close(start)
	invites.arrived.Wait()
	wg.Wait()

	if got := invites.peak.Load(); got != 1 {
		t.Fatalf("same-target peak inflight = %d, want 1", got)
	}

	if got := invites.mints.Load(); got != 1 {
		t.Fatalf("same-target mints = %d, want 1", got)
	}

	handles := env.runner.liveHandles()
	if len(handles) != 1 || env.runner.lookupHandle(runID) == nil {
		t.Fatalf("handles = %d, want one handle for %s", len(handles), runID)
	}
}

func TestReapOnce_UpdatedAtRaceMissesTerminalWrite(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	env := newDriveEnv(t, &driveInvites{}, func() time.Time { return now }, 10)
	ctx := t.Context()
	runID := "run-watchdog-race"
	observedAt := now.Unix() - 100

	seedDriveRun(t, env.store, runID, "idle.example", validatorcore.StateActiveRunning)
	mustUpdate(t, env.store, runID, "updated_at", observedAt)

	var captured atomic.Int64

	const cbName = "test_reap_advance_updated_at"

	if err := env.store.DB().Callback().Query().After("gorm:query").Register(cbName, func(db *gorm.DB) {
		dest, ok := db.Statement.Dest.(*validatorcore.TestRun)
		if !ok || dest.TestRunID != runID || !captured.CompareAndSwap(0, dest.UpdatedAt) {
			return
		}

		if updErr := env.store.DB().WithContext(ctx).Model(&validatorcore.TestRun{}).
			Where("test_run_id = ?", runID).
			UpdateColumn("updated_at", dest.UpdatedAt+50).Error; updErr != nil {
			t.Errorf("advance updated_at after observe: %v", updErr)
		}
	}); err != nil {
		t.Fatalf("register observe seam: %v", err)
	}

	t.Cleanup(func() {
		if err := env.store.DB().Callback().Query().Remove(cbName); err != nil {
			t.Errorf("remove observe seam: %v", err)
		}
	})
	env.runner.ReapOnce()

	stale := captured.Load()
	if stale != observedAt {
		t.Fatalf("reaper observed updated_at = %d, want %d", stale, observedAt)
	}

	requireLiveDriveRun(t, env.store, runID, observedAt+50)

	writeErr := env.store.WriteTerminalObserved(
		ctx,
		runID,
		true,
		validatorcore.StateActiveRunning,
		stale,
		validatorcore.ActiveTerminalUpdate{
			State:          validatorcore.StateInterrupted,
			TerminalReason: validatorcore.ReasonActiveDriveTimeout,
		},
	)
	if !errors.Is(writeErr, validatorcore.ErrStateTransitionMiss) {
		t.Fatalf("WriteTerminalObserved = %v, want ErrStateTransitionMiss", writeErr)
	}

	requireLiveDriveRun(t, env.store, runID, observedAt+50)
}

type driveEnv struct {
	store   *validatorcore.Core
	runner  *Runner
	invites *driveInvites
}

func newDriveEnv(t *testing.T, invites InviteDriver, now func() time.Time, idle int) *driveEnv {
	t.Helper()

	store, parties, _ := openDriveStore(t)

	tracked, ok := invites.(*driveInvites)
	if !ok && invites == nil {
		tracked = &driveInvites{}
		invites = tracked
	}

	return &driveEnv{store: store, runner: mustRunner(t, store, parties, invites, now, idle), invites: tracked}
}

func newCycleHandle(t *testing.T, r *Runner, runID string) *sessionHandle {
	t.Helper()

	ctx, cancel := context.WithCancel(r.ctx)
	t.Cleanup(cancel)

	return &sessionHandle{id: runID, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), done: make(chan struct{})}
}

func mustRunner(
	t *testing.T,
	store *validatorcore.Core,
	parties identity.PartyRepo,
	invites InviteDriver,
	now func() time.Time,
	idle int,
) *Runner {
	t.Helper()

	active, err := New(Deps{
		Store:               store,
		Invites:             invites,
		Parties:             parties,
		LocalIdentity:       driveLocalIdentity(),
		ProbeEmail:          "probe@localhost",
		ProbeName:           "Probe User",
		ProbeFilePath:       "probe.txt",
		ReapIntervalSeconds: 3600,
		MaxDriveIdleSeconds: idle,
		Now:                 now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return active
}

func openDriveStore(t *testing.T) (*validatorcore.Core, *identity.MemoryPartyRepo, *repos.Repos) {
	t.Helper()

	r, err := repos.New(t.Context(), config.PersistenceConfig{Backend: config.BackendSQLite, DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("repos.New: %v", err)
	}

	t.Cleanup(func() { tshttp.MustClose(t, r) })

	db, err := r.SharedDB()
	if err != nil {
		t.Fatalf("SharedDB: %v", err)
	}

	store, err := validatorcore.Attach(db, validatorcore.DefaultSessionConfig())
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}

	return store, identity.NewMemoryPartyRepo(), r
}

func driveLocalIdentity() localidentity.Identity {
	return localidentity.Identity{
		Origin: "https://local.example", Scheme: "https",
		ProviderDomain: "local.example", ProviderDomainCompare: "local.example",
	}
}

func seedDriveRun(t *testing.T, store *validatorcore.Core, runID, host, state string) {
	t.Helper()

	now := time.Now().Unix()
	if err := store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID: runID, IsActive: true, State: state,
		TargetOrigin: "https://" + host, TargetHost: host,
		DiscoveryURL: "https://" + host + "/.well-known/ocm",
		CreatedAt:    now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed run %s: %v", runID, err)
	}
}

func bindDriveBob(t *testing.T, store *validatorcore.Core, runID string) {
	t.Helper()
	mustUpdate(t, store, runID, "bob_user_id", "bob-"+runID)
}

func mustUpdate(t *testing.T, store *validatorcore.Core, runID, column string, value any) {
	t.Helper()

	if err := store.DB().WithContext(t.Context()).Model(&validatorcore.TestRun{}).
		Where("test_run_id = ?", runID).UpdateColumn(column, value).Error; err != nil {
		t.Fatalf("update %s: %v", column, err)
	}
}

func requireLiveDriveRun(t *testing.T, store *validatorcore.Core, runID string, wantUpdatedAt int64) {
	t.Helper()

	got, err := store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	live := got.IsActive && got.State == validatorcore.StateActiveRunning &&
		got.UpdatedAt == wantUpdatedAt && got.FinishedAt == nil && got.TerminalReason == nil
	if !live {
		t.Fatalf("row %+v, want live active_running @ %d", got, wantUpdatedAt)
	}
}

type driveInvites struct {
	mu    sync.Mutex
	byRun map[string]int
	mints atomic.Int32
}

func (s *driveInvites) MintOutgoingInvite(_ context.Context, testRunID string) (*invitesoutgoing.OutgoingInvite, error) {
	s.mints.Add(1)
	s.mu.Lock()

	if s.byRun == nil {
		s.byRun = map[string]int{}
	}

	s.byRun[testRunID]++
	s.mu.Unlock()

	return &invitesoutgoing.OutgoingInvite{ID: "invite-" + testRunID, Token: "tok-" + testRunID}, nil
}

func (s *driveInvites) SolicitReverse(context.Context, string) error { return nil }

func (s *driveInvites) count(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.byRun[id]
}

type barrierInvites struct {
	arrived   sync.WaitGroup
	release   chan struct{}
	maxArrive int32
	inflight  atomic.Int32
	peak      atomic.Int32
	mints     atomic.Int32
}

func (b *barrierInvites) MintOutgoingInvite(ctx context.Context, testRunID string) (*invitesoutgoing.OutgoingInvite, error) {
	n := b.mints.Add(1)
	cur := b.inflight.Add(1)

	for {
		old := b.peak.Load()
		if cur <= old || b.peak.CompareAndSwap(old, cur) {
			break
		}
	}

	if b.maxArrive == 0 || n <= b.maxArrive {
		b.arrived.Done()
	}

	defer b.inflight.Add(-1)

	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, fmt.Errorf("barrier mint canceled: %w", ctx.Err())
	}

	return &invitesoutgoing.OutgoingInvite{ID: "invite-" + testRunID, Token: "tok-" + testRunID}, nil
}

func (b *barrierInvites) SolicitReverse(context.Context, string) error { return nil }
