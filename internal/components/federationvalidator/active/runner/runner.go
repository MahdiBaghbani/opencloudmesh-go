// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package runner drives the validator active-session kick and heal loop.
package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const (
	defaultDriveWorkers = 16
	defaultReapSeconds  = 1
	defaultIdleSeconds  = 1800
)

// InviteDriver is the reverse-invite mint and solicit surface the runner
// heals through. Production wires reverseinvite.Service.
type InviteDriver interface {
	MintOutgoingInvite(ctx context.Context, testRunID string) (*invitesoutgoing.OutgoingInvite, error)
	SolicitReverse(ctx context.Context, testRunID string) error
}

// OutgoingCreator is the programmatic designated-share entry. Production
// wires outgoingshares.Handler.CreateAsUser.
type OutgoingCreator interface {
	CreateAsUser(
		ctx context.Context,
		user *identity.User,
		req sharesoutgoing.OutgoingShareRequest,
	) (*sharesoutgoing.OutgoingShare, error)
}

// Deps are the constructor dependencies for the active runner.
type Deps struct {
	Store               *validatorcore.Core
	Invites             InviteDriver
	Parties             identity.PartyRepo
	LocalIdentity       localidentity.Identity
	ProbeEmail          string
	ProbeName           string
	ProbeFilePath       string
	Log                 *slog.Logger
	MaxDriveIdleSeconds int
	ReapIntervalSeconds int
	SessionLimit        int
	MaxDispatchAttempts int
	BackoffBaseSeconds  int
	BackoffCapSeconds   int
	Now                 func() time.Time
}

// sessionHandle is the per-session owner used by the supervisor and
// watchdog. It holds the session context, wake channel, park backoff,
// and dispatch retry state. mu guards backoff so the watchdog can skip
// a pending-retry handle without racing the session goroutine. A
// supervisor-owned handle runs its own goroutine; a silent ReapOnce
// handle does not.
type sessionHandle struct {
	id      string
	ctx     context.Context //nolint:containedctx // handle-owned lifecycle canceled by Stop
	cancel  context.CancelFunc
	wake    chan struct{}
	done    chan struct{}
	mu      sync.Mutex // guards backoff
	backoff sessionBackoff
	retry   *driveRetryState
	silent  bool
}

// Runner is the long-lived active-session supervisor.
type Runner struct {
	store      *validatorcore.Core
	invites    InviteDriver
	parties    identity.PartyRepo
	local      localidentity.Identity
	probeEmail string
	probeName  string
	probePath  string
	log        *slog.Logger
	session    validatorcore.SessionConfig

	outgoingMu sync.RWMutex
	outgoing   OutgoingCreator

	handlesMu    sync.Mutex
	handles      map[string]*sessionHandle
	drivePermits chan struct{}
	sessionWG    sync.WaitGroup

	// driveOnceRetry is DriveOnce-only dispatch/in-progress state.
	// DriveOnce is a synchronous one-shot and must not insert sessionHandle
	// entries: that would start a supervisor goroutine and make later
	// ensureHandle a no-op. Keyed by session ID, scoped to this Runner
	// so it cannot leak across instances. Successful dispatch keeps the
	// entry with lastProgress so ReapOnce can skip idle timeout without
	// bumping updated_at. clearDriveRetry still runs on hard fail,
	// observed terminalization, and handle exit.
	driveOnceRetry driveRetryBook

	nowFn func() time.Time

	wake         chan struct{}
	stop         chan struct{}
	done         chan struct{}
	watchdogDone chan struct{}
	ctx          context.Context //nolint:containedctx // runner-owned lifecycle context canceled by Stop
	cancel       context.CancelFunc
	startOnce    sync.Once
	stopOnce     sync.Once
}

// New constructs a stopped runner. BindOutgoing then Start.
func New(deps Deps) (*Runner, error) {
	switch {
	case deps.Store == nil:
		return nil, errors.New("runner: Store is required")
	case deps.Invites == nil:
		return nil, errors.New("runner: Invites is required")
	case deps.Parties == nil:
		return nil, errors.New("runner: Parties is required")
	case deps.LocalIdentity.ProviderDomain == "":
		return nil, errors.New("runner: LocalIdentity.ProviderDomain is required")
	case deps.LocalIdentity.Scheme == "":
		return nil, errors.New("runner: LocalIdentity.Scheme is required")
	}

	session := resolveSessionKnobs(deps)

	ctx, cancel := context.WithCancel(context.Background())

	return &Runner{
		store:          deps.Store,
		invites:        deps.Invites,
		parties:        deps.Parties,
		local:          deps.LocalIdentity,
		probeEmail:     deps.ProbeEmail,
		probeName:      deps.ProbeName,
		probePath:      deps.ProbeFilePath,
		log:            logutil.NoopIfNil(deps.Log),
		session:        session,
		handles:        map[string]*sessionHandle{},
		driveOnceRetry: driveRetryBook{byRun: map[string]*driveRetryState{}},
		drivePermits:   make(chan struct{}, driveWorkerCap(session.SessionLimit)),
		nowFn:          deps.Now,
		wake:           make(chan struct{}, 1),
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
		watchdogDone:   make(chan struct{}),
		ctx:            ctx,
		cancel:         cancel,
	}, nil
}

// BindOutgoing installs the outgoing-share creator. Call before Start so a
// reverse_invite_accepted run can dispatch on the first tick.
func (r *Runner) BindOutgoing(creator OutgoingCreator) {
	if r == nil {
		return
	}

	r.outgoingMu.Lock()
	defer r.outgoingMu.Unlock()

	r.outgoing = creator
}

// Kick is the wake-only ActiveKicker. It carries no IDs. A full buffer
// drops the extra signal because the supervisor resyncs from store state.
func (r *Runner) Kick() {
	if r == nil {
		return
	}

	select {
	case <-r.stop:
		return
	default:
	}

	select {
	case r.wake <- struct{}{}:
	default:
	}

	r.wakeAllHandles()
}

// Start launches the supervisor and watchdog. Repeated calls are no-ops.
func (r *Runner) Start() {
	if r == nil {
		return
	}

	r.startOnce.Do(func() {
		go r.loop()
		go r.watchdogLoop()
	})
}

// Stop cancels the runner context, then joins the supervisor, watchdog,
// and every live session goroutine. Safe before Start and after Stop.
func (r *Runner) Stop() {
	if r == nil {
		return
	}

	if r.cancel != nil {
		r.cancel()
	}

	r.stopOnce.Do(func() {
		close(r.stop)
	})
	r.startOnce.Do(func() {
		close(r.done)
		close(r.watchdogDone)
	})
	<-r.done
	<-r.watchdogDone
	r.sessionWG.Wait()
	r.dropSilentHandles()
}

func (r *Runner) dropSilentHandles() {
	if r == nil {
		return
	}

	r.handlesMu.Lock()
	leftover := make([]*sessionHandle, 0, len(r.handles))

	for id, h := range r.handles {
		if h == nil || !h.silent {
			continue
		}

		delete(r.handles, id)

		leftover = append(leftover, h)
	}

	r.handlesMu.Unlock()

	for _, h := range leftover {
		h.cancel()

		select {
		case <-h.done:
		default:
			close(h.done)
		}

		r.driveOnceRetry.delete(h.id)
	}
}

func (r *Runner) outgoingCreator() OutgoingCreator {
	if r == nil {
		return nil
	}

	r.outgoingMu.RLock()
	defer r.outgoingMu.RUnlock()

	return r.outgoing
}

func (r *Runner) now() time.Time {
	if r != nil && r.nowFn != nil {
		return r.nowFn()
	}

	return time.Now()
}

func (r *Runner) loop() {
	defer close(r.done)

	ticker := time.NewTicker(r.reapInterval())
	defer ticker.Stop()

	r.syncHandles(r.ctx)

	for {
		select {
		case <-r.stop:
			return
		case <-r.wake:
			r.syncHandles(r.ctx)
		case <-ticker.C:
			r.syncHandles(r.ctx)
		}
	}
}

func (r *Runner) syncHandles(ctx context.Context) {
	if r == nil || r.store == nil || ctx.Err() != nil {
		return
	}

	r.promoteReadyWaiter(ctx)

	rows, err := r.store.ListActive(ctx)
	if err != nil {
		r.log.Warn("active runner: list active runs", "error", err)

		return
	}

	for _, row := range rows {
		if row != nil {
			r.ensureHandle(row.TestRunID)
		}
	}
}

func (r *Runner) watchdogLoop() {
	defer close(r.watchdogDone)

	ticker := time.NewTicker(r.reapInterval())
	defer ticker.Stop()

	for {
		select {
		case <-r.stop:
			return
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.reapLiveHandles()
		}
	}
}

func (r *Runner) reapLiveHandles() {
	if r == nil || r.store == nil {
		return
	}

	idle := r.maxDriveIdleSeconds()
	if idle <= 0 {
		return
	}

	now := r.now().Unix()

	for _, h := range r.liveHandles() {
		r.reapIdleHandle(r.ctx, h, now, idle)
	}
}

func (r *Runner) reapIdleHandle(
	ctx context.Context,
	h *sessionHandle,
	now int64,
	idle int64,
) {
	if h == nil {
		return
	}

	observed, err := r.observeSession(ctx, h.id)
	if err != nil {
		r.log.Warn("active runner: observe session", "test_run_id", h.id, "error", err)

		return
	}

	if observed == nil {
		return
	}

	if !observed.IsActive || !isDriveWorkState(observed.State) {
		return
	}

	if r.handleAwaitingRetry(h) {
		return
	}

	if now-observed.UpdatedAt < idle {
		return
	}

	// Observed snapshot is the write input. State and updated_at both
	// guard the UPDATE so a stale snapshot cannot win after progress.
	r.writeObservedDriveTimeout(ctx, observed)
}

// observeSession is the session observation path the watchdog and
// guarded write use. A stale snapshot must not be retried.
func (r *Runner) observeSession(
	ctx context.Context,
	testRunID string,
) (*validatorcore.TestRun, error) {
	if r == nil || r.store == nil {
		return nil, errors.New("runner: store is not configured")
	}

	run, err := r.store.GetTestRun(ctx, testRunID)
	if err != nil {
		return nil, fmt.Errorf("runner: get test run: %w", err)
	}

	return run, nil
}

// writeObservedDriveTimeout terminalizes an idle drive from one
// observation. Transition misses are benign progress: a changed state
// or updated_at leaves the row live and is not retried. Unrelated
// errors are logged.
func (r *Runner) writeObservedDriveTimeout(
	ctx context.Context,
	observed *validatorcore.TestRun,
) {
	if r == nil || r.store == nil || observed == nil {
		return
	}

	err := r.store.WriteTerminalObserved(
		ctx,
		observed.TestRunID,
		true,
		observed.State,
		observed.UpdatedAt,
		validatorcore.ActiveTerminalUpdate{
			State:          validatorcore.StateInterrupted,
			TerminalReason: validatorcore.ReasonActiveDriveTimeout,
		},
	)
	if err == nil {
		r.clearDriveRetry(observed.TestRunID)

		return
	}

	if errors.Is(err, validatorcore.ErrStateTransitionMiss) {
		return
	}

	r.log.Warn(
		"active runner: observed drive timeout write",
		"test_run_id",
		observed.TestRunID,
		"error",
		err,
	)
}

func (r *Runner) reapInterval() time.Duration {
	sec := r.sessionConfig().ReapIntervalSeconds
	if sec <= 0 {
		sec = defaultReapSeconds
	}

	return time.Duration(sec) * time.Second
}

func (r *Runner) maxDriveIdleSeconds() int64 {
	n := r.sessionConfig().MaxDriveIdleSeconds
	if n <= 0 {
		return defaultIdleSeconds
	}

	return int64(n)
}
