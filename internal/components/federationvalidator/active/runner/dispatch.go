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
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// driveRetryState keeps the dispatch-failure schedule and the
// in-progress schedule separate. In-progress waits never increment
// dispatchAttempts. lastProgress is successful-dispatch live
// progress for the watchdog only: it must not bump updated_at
// (that would hide a stuck remote) and must not leave a retry wait
// (that would consume the next cycle's fresh budget).
type driveRetryState struct {
	mu               sync.Mutex
	dispatchAttempts int
	dispatch         sessionBackoff
	inProgress       sessionBackoff
	lastProgress     time.Time
}

type driveRetryBook struct {
	mu    sync.Mutex
	byRun map[string]*driveRetryState
}

func (st *driveRetryState) dispatchWaiting(now time.Time) bool {
	if st == nil {
		return false
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	return st.dispatch.waitDuration(now) > 0
}

func (st *driveRetryState) inProgressWaiting(now time.Time) bool {
	if st == nil {
		return false
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	return st.inProgress.waitDuration(now) > 0
}

func (st *driveRetryState) recordDispatchFailure(cfg validatorcore.SessionConfig, now time.Time) int {
	if st == nil {
		return 0
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	st.dispatch.recordFailure(cfg, now)
	st.dispatchAttempts++

	return st.dispatchAttempts
}

func (st *driveRetryState) recordInProgress(cfg validatorcore.SessionConfig, now time.Time) {
	if st == nil {
		return
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	st.inProgress.recordFailure(cfg, now)
}

func (st *driveRetryState) reset() {
	if st == nil {
		return
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	st.dispatchAttempts = 0
	st.dispatch.reset()
	st.inProgress.reset()
	st.lastProgress = time.Time{}
}

func (st *driveRetryState) noteProgress(now time.Time) {
	if st == nil {
		return
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	st.dispatchAttempts = 0
	st.dispatch.reset()
	st.inProgress.reset()
	st.lastProgress = now
}

func (st *driveRetryState) recentlyProgressed(now time.Time, idle time.Duration) bool {
	if st == nil || idle <= 0 {
		return false
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if st.lastProgress.IsZero() {
		return false
	}

	return now.Sub(st.lastProgress) < idle
}

func (b *driveRetryBook) get(id string) *driveRetryState {
	if b == nil || id == "" {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.byRun == nil {
		b.byRun = map[string]*driveRetryState{}
	}

	st, ok := b.byRun[id]
	if !ok {
		st = &driveRetryState{}
		b.byRun[id] = st
	}

	return st
}

func (b *driveRetryBook) lookup(id string) *driveRetryState {
	if b == nil || id == "" {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	return b.byRun[id]
}

func (b *driveRetryBook) takeOrNew(id string) *driveRetryState {
	if b == nil || id == "" {
		return &driveRetryState{}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	st := b.byRun[id]
	delete(b.byRun, id)

	if st == nil {
		st = &driveRetryState{}
	}

	return st
}

func (b *driveRetryBook) delete(id string) {
	if b == nil || id == "" {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.byRun, id)
}

func (r *Runner) retryStateFor(id string, h *sessionHandle, create bool) *driveRetryState {
	if h != nil {
		if h.retry == nil {
			h.retry = &driveRetryState{}
		}

		return h.retry
	}

	if live := r.lookupHandle(id); live != nil {
		if live.retry == nil {
			live.retry = &driveRetryState{}
		}

		return live.retry
	}

	if create {
		return r.driveOnceRetry.get(id)
	}

	return r.driveOnceRetry.lookup(id)
}

func (r *Runner) awaitingDispatchBackoff(run *validatorcore.TestRun, h *sessionHandle) bool {
	if r == nil || run == nil {
		return false
	}

	return r.retryStateFor(run.TestRunID, h, false).dispatchWaiting(r.now())
}

func (r *Runner) awaitingInProgressBackoff(run *validatorcore.TestRun, h *sessionHandle) bool {
	if r == nil || run == nil {
		return false
	}

	return r.retryStateFor(run.TestRunID, h, false).inProgressWaiting(r.now())
}

func (r *Runner) handleAwaitingRetry(h *sessionHandle) bool {
	if r == nil || h == nil {
		return false
	}

	now := r.now()
	if h.backoffWait(now) > 0 {
		return true
	}

	if h.retry.dispatchWaiting(now) || h.retry.inProgressWaiting(now) {
		return true
	}

	idle := time.Duration(r.maxDriveIdleSeconds()) * time.Second

	return h.retry.recentlyProgressed(now, idle)
}

func (r *Runner) noteDispatchFailure(run *validatorcore.TestRun, h *sessionHandle) bool {
	if r == nil || run == nil {
		return false
	}

	cfg := r.sessionConfig()
	maxAttempts := cfg.MaxDispatchAttempts

	if maxAttempts <= 0 {
		maxAttempts = validatorcore.DefaultSessionConfig().MaxDispatchAttempts
	}

	st := r.retryStateFor(run.TestRunID, h, true)
	attempts := st.recordDispatchFailure(cfg, r.now())

	return attempts >= maxAttempts
}

func (r *Runner) noteInProgressRetry(run *validatorcore.TestRun, h *sessionHandle) {
	if r == nil || run == nil {
		return
	}

	r.retryStateFor(run.TestRunID, h, true).recordInProgress(r.sessionConfig(), r.now())
}

func (r *Runner) clearDriveRetry(testRunID string) {
	if testRunID == "" {
		return
	}

	if h := r.lookupHandle(testRunID); h != nil {
		h.retry.reset()
	}

	r.driveOnceRetry.delete(testRunID)
}

// noteDispatchSuccess resets retry waits for a fresh next-cycle budget
// and records lastProgress. DriveOnce has no handle, so the book entry
// must stay: ReapOnce attaches it as the ephemeral handle's retry.
// Deleting it would leave an aged row with no watchdog skip.
func (r *Runner) noteDispatchSuccess(run *validatorcore.TestRun, h *sessionHandle) {
	if r == nil || run == nil {
		return
	}

	r.retryStateFor(run.TestRunID, h, true).noteProgress(r.now())

	if h != nil || r.lookupHandle(run.TestRunID) != nil {
		r.driveOnceRetry.delete(run.TestRunID)
	}
}

func (r *Runner) driveDispatch(ctx context.Context, run *validatorcore.TestRun, h *sessionHandle) {
	if r.awaitingDispatchBackoff(run, h) || r.awaitingInProgressBackoff(run, h) {
		return
	}

	creator := r.outgoingCreator()
	if creator == nil {
		r.log.Warn("active runner: outgoing creator is not bound", "test_run_id", run.TestRunID)

		return
	}

	alice, err := identity.EnsureSessionInviter(ctx, r.parties, run.TestRunID, r.local.ProviderDomain)
	if err != nil {
		r.handleDriveErr(
			ctx,
			run,
			err,
			h,
		)

		return
	}

	req, err := designatedShareRequest(run, r.probePath, r.local.Scheme)
	if err != nil {
		r.handleDriveErr(
			ctx,
			run,
			err,
			h,
		)

		return
	}

	if _, err := creator.CreateAsUser(ctx, alice, req); err != nil {
		r.handleDriveErr(
			ctx,
			run,
			err,
			h,
		)

		return
	}

	r.noteDispatchSuccess(run, h)
}

func designatedShareRequest(
	run *validatorcore.TestRun,
	probePath, scheme string,
) (sharesoutgoing.OutgoingShareRequest, error) {
	shareWith, err := designatedShareWith(run, scheme)
	if err != nil {
		return sharesoutgoing.OutgoingShareRequest{}, err
	}

	if probePath == "" {
		return sharesoutgoing.OutgoingShareRequest{}, errors.New("runner: probe file path is required")
	}

	return sharesoutgoing.OutgoingShareRequest{
		ReceiverDomain: run.TargetHost,
		ShareWith:      shareWith,
		LocalPath:      probePath,
		Permissions:    append([]string{}, spec.SupportedWebDAVPermissions...),
	}, nil
}

func designatedShareWith(run *validatorcore.TestRun, scheme string) (string, error) {
	if run.DesignatedShareWith == nil || *run.DesignatedShareWith == "" {
		return "", fmt.Errorf("runner: %w", validatorcore.ErrShareCorrelationConflict)
	}

	raw := *run.DesignatedShareWith

	user, provider, err := address.Parse(raw)
	if err != nil {
		user, provider = raw, run.TargetHost
	}

	normalized, err := hostport.Normalize(provider, scheme)
	if err != nil || normalized != run.TargetHost {
		return "", fmt.Errorf("runner: %w", validatorcore.ErrShareCorrelationConflict)
	}

	return user + "@" + normalized, nil
}
