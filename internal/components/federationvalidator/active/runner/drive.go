// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package runner

import (
	"context"
	"errors"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// DriveOnce is the synchronous one-shot used by tests and callers that
// do not run the supervisor. It lists every is_active=1 row, drives
// each, then promotes ready waiters. An empty list promotes and
// returns so a just-promoted run is not driven in the same call.
func (r *Runner) DriveOnce(ctx context.Context) {
	if r == nil || r.store == nil {
		return
	}

	if err := ctx.Err(); err != nil {
		return
	}

	rows, err := r.store.ListActive(ctx)
	if err != nil {
		r.log.Warn("active runner: list active runs", "error", err)

		return
	}

	if len(rows) == 0 {
		r.promoteReadyWaiter(ctx)

		return
	}

	for _, run := range rows {
		r.driveActive(ctx, run, nil)
	}

	r.promoteReadyWaiter(ctx)
}

// ReapOnce is the synchronous watchdog one-shot for callers that do
// not run the supervisor. DriveOnce does not insert handles, so this
// call attaches ephemeral live handles for current drive-work rows
// (sharing any DriveOnce retry state), applies the same live-handle
// idle check as watchdogLoop, then releases those handles so a later
// Start still owns the session goroutine.
func (r *Runner) ReapOnce() {
	if r == nil {
		return
	}

	ephemeral := r.attachEphemeralDriveHandles()
	defer r.releaseEphemeralHandles(ephemeral)

	r.reapLiveHandles()
}

func (r *Runner) attachEphemeralDriveHandles() []string {
	if r == nil || r.store == nil || r.ctx.Err() != nil {
		return []string{}
	}

	rows, err := r.store.ListActive(r.ctx)
	if err != nil {
		r.log.Warn("active runner: list active runs", "error", err)

		return []string{}
	}

	attached := make([]string, 0)

	for _, run := range rows {
		if run == nil || !isDriveWorkState(run.State) {
			continue
		}

		if r.attachEphemeralHandle(run.TestRunID) {
			attached = append(attached, run.TestRunID)
		}
	}

	return attached
}

func (r *Runner) attachEphemeralHandle(id string) bool {
	if r == nil || id == "" {
		return false
	}

	r.handlesMu.Lock()
	defer r.handlesMu.Unlock()

	if _, ok := r.handles[id]; ok {
		return false
	}

	select {
	case <-r.stop:
		return false
	default:
	}

	if r.ctx.Err() != nil {
		return false
	}

	ctx, cancel := context.WithCancel(r.ctx)
	r.handles[id] = &sessionHandle{
		id:     id,
		ctx:    ctx,
		cancel: cancel,
		wake:   make(chan struct{}, 1),
		done:   make(chan struct{}),
		retry:  r.driveOnceRetry.lookup(id),
		silent: true,
	}

	return true
}

func (r *Runner) releaseEphemeralHandles(ids []string) {
	for _, id := range ids {
		r.releaseEphemeralHandle(id)
	}
}

func (r *Runner) releaseEphemeralHandle(id string) {
	if r == nil || id == "" {
		return
	}

	r.handlesMu.Lock()

	h, ok := r.handles[id]
	if ok && h.silent {
		delete(r.handles, id)
	} else {
		ok = false
	}
	r.handlesMu.Unlock()

	if !ok {
		return
	}

	h.cancel()
	close(h.done)
}

func (r *Runner) driveActive(ctx context.Context, run *validatorcore.TestRun, h *sessionHandle) {
	if run == nil {
		return
	}

	switch run.State {
	case validatorcore.StateActiveRunning:
		r.driveFirstMile(ctx, run, h)
	case validatorcore.StateInviteAccepted:
		r.driveSolicit(ctx, run, h)
	case validatorcore.StateReverseInviteAccepted:
		r.driveDispatch(ctx, run, h)
	case validatorcore.StateCapabilityExercise, validatorcore.StateReverseAwaitingShare:
		// Peer waits are clocked by the stall sweep from updated_at age.
		// Refreshing the stamp would hide a stuck remote and hold the
		// active lock forever.
		return
	}
}

func (r *Runner) promoteReadyWaiter(ctx context.Context) {
	err := r.store.PromoteOldestReadyWaiter(ctx)
	if err == nil {
		return
	}

	r.log.Warn("active runner: promote ready waiter", "error", err)
}

// driveSessionCycle observes one handle, parks wait states without a
// permit, and try-acquires before drive work. false means the handle
// should exit.
func (r *Runner) driveSessionCycle(h *sessionHandle) bool {
	if r == nil || h == nil {
		return false
	}

	observed, err := r.observeSession(h.ctx, h.id)
	if err != nil {
		if observeFatal(err, h.ctx) {
			return false
		}

		r.log.Warn("active runner: observe session", "test_run_id", h.id, "error", err)

		return true
	}

	if !sessionStillLive(observed) {
		return false
	}

	if !isDriveWorkState(observed.State) {
		r.driveActive(h.ctx, observed, h)
		h.resetBackoff()

		return true
	}

	if wait := h.backoffWait(r.now()); wait > 0 {
		return true
	}

	// Dispatch and in-progress retry waits are not handle park
	// backoff. Kick resets only the handle delay; a cycle that
	// acquired a permit and then no-op'd in driveDispatch used to
	// stack a new handle delay on top of the real retry wait.
	if r.awaitingDispatchBackoff(observed, h) || r.awaitingInProgressBackoff(observed, h) {
		return true
	}

	if !r.tryAcquireDrive() {
		return true
	}
	defer r.releaseDrive()

	r.driveActive(h.ctx, observed, h)

	after, afterErr := r.observeSession(h.ctx, h.id)
	if afterErr != nil {
		if observeFatal(afterErr, h.ctx) {
			return false
		}

		r.log.Warn("active runner: observe session", "test_run_id", h.id, "error", afterErr)

		return true
	}

	if !sessionStillLive(after) {
		return false
	}

	if isDriveWorkState(after.State) {
		h.recordBackoffFailure(r.sessionConfig(), r.now())
	} else {
		h.resetBackoff()
	}

	return true
}

func (r *Runner) tryAcquireDrive() bool {
	if r == nil || r.drivePermits == nil {
		return false
	}

	select {
	case r.drivePermits <- struct{}{}:
		return true
	default:
		return false
	}
}

func (r *Runner) releaseDrive() {
	if r == nil || r.drivePermits == nil {
		return
	}

	select {
	case <-r.drivePermits:
	default:
	}
}

func (r *Runner) parkDuration(h *sessionHandle) time.Duration {
	if h != nil {
		if wait := h.backoffWait(r.now()); wait > 0 {
			return wait
		}
	}

	if r != nil {
		return r.reapInterval()
	}

	return time.Duration(validatorcore.DefaultSessionConfig().ReapIntervalSeconds) * time.Second
}

func isDriveWorkState(state string) bool {
	switch state {
	case validatorcore.StateActiveRunning,
		validatorcore.StateInviteAccepted,
		validatorcore.StateReverseInviteAccepted:
		return true
	default:
		return false
	}
}

func isTerminalRunState(state string) bool {
	switch state {
	case validatorcore.StateTerminalPass,
		validatorcore.StateTerminalFail,
		validatorcore.StateInterrupted:
		return true
	default:
		return false
	}
}

func sessionStillLive(run *validatorcore.TestRun) bool {
	return run != nil && run.IsActive && !isTerminalRunState(run.State)
}

func observeFatal(err error, ctx context.Context) bool {
	return errors.Is(err, validatorcore.ErrSessionNotFound) || ctx.Err() != nil
}

func (r *Runner) ensureHandle(id string) {
	if r == nil || id == "" {
		return
	}

	r.handlesMu.Lock()
	if _, ok := r.handles[id]; ok {
		r.handlesMu.Unlock()

		return
	}

	select {
	case <-r.stop:
		r.handlesMu.Unlock()

		return
	default:
	}

	if r.ctx.Err() != nil {
		r.handlesMu.Unlock()

		return
	}

	ctx, cancel := context.WithCancel(r.ctx)
	h := &sessionHandle{
		id:     id,
		ctx:    ctx,
		cancel: cancel,
		wake:   make(chan struct{}, 1),
		done:   make(chan struct{}),
		retry:  r.driveOnceRetry.takeOrNew(id),
	}
	r.handles[id] = h
	r.sessionWG.Add(1)
	r.handlesMu.Unlock()

	go r.runSession(h)
}

func (r *Runner) dropHandle(id string) {
	if r == nil || id == "" {
		return
	}

	r.handlesMu.Lock()
	h, ok := r.handles[id]

	if ok {
		delete(r.handles, id)
	}

	r.handlesMu.Unlock()

	r.clearDriveRetry(id)

	if ok {
		h.cancel()
	}
}

func (r *Runner) runSession(h *sessionHandle) {
	defer close(h.done)
	defer r.sessionWG.Done()
	defer r.dropHandle(h.id)

	if !r.driveSessionCycle(h) {
		return
	}

	timer := time.NewTimer(r.parkDuration(h))
	defer timer.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-r.stop:
			return
		case <-h.wake:
			h.resetBackoff()

			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}

		if !r.driveSessionCycle(h) {
			return
		}

		timer.Reset(r.parkDuration(h))
	}
}

func (r *Runner) wakeAllHandles() {
	for _, h := range r.liveHandles() {
		select {
		case h.wake <- struct{}{}:
		default:
		}
	}
}

func (r *Runner) lookupHandle(id string) *sessionHandle {
	if r == nil || id == "" {
		return nil
	}

	r.handlesMu.Lock()
	defer r.handlesMu.Unlock()

	return r.handles[id]
}

func (r *Runner) liveHandles() []*sessionHandle {
	if r == nil {
		return []*sessionHandle{}
	}

	r.handlesMu.Lock()
	defer r.handlesMu.Unlock()

	out := make([]*sessionHandle, 0, len(r.handles))
	for _, h := range r.handles {
		out = append(out, h)
	}

	return out
}
