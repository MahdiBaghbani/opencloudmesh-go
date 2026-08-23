// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package runner_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/runner"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestRunner_KickDoesNotBlockWhenBufferFull(t *testing.T) {
	t.Parallel()

	env := newStubEnv(t, nil, nil)

	done := make(chan struct{})

	go func() {
		env.runner.Kick()
		env.runner.Kick()
		env.runner.Kick()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Kick blocked on a full wake buffer")
	}
}

func TestRunner_StopJoinsWithoutStart(t *testing.T) {
	t.Parallel()

	env := newStubEnv(t, nil, nil)

	done := make(chan struct{})

	go func() {
		env.runner.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return before Start")
	}

	env.runner.Stop()
}

func TestRunner_StartStopJoin(t *testing.T) {
	t.Parallel()

	env := newStubEnv(t, nil, nil)
	env.runner.Start()
	env.runner.Kick()

	done := make(chan struct{})

	go func() {
		env.runner.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not join the runner")
	}
}

func TestRunner_StopCancelsInFlightDrive(t *testing.T) {
	t.Parallel()

	invites := newBlockingInvites()
	env := newStubEnv(t, invites, nil)
	runID := "run-stop-cancel"

	env.seedActive(t, runID, validatorcore.StateActiveRunning)
	env.bindBob(t, runID)

	env.runner.Start()

	select {
	case <-invites.started:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight mint did not start")
	}

	done := make(chan struct{})

	go func() {
		env.runner.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return while a drive was blocked")
	}

	if err := invites.err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("in-flight mint err = %v, want %v", err, context.Canceled)
	}
}

func TestRunner_KickAfterStopIsNoop(t *testing.T) {
	t.Parallel()

	env := newStubEnv(t, nil, nil)
	env.runner.Start()
	env.runner.Stop()

	done := make(chan struct{})

	go func() {
		env.runner.Kick()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Kick after Stop blocked")
	}
}

func TestRunner_KickWakesMint(t *testing.T) {
	t.Parallel()

	env := newRealInviteEnv(t)
	runID := "run-kick-wake"

	env.seedActive(t, runID, validatorcore.StateActiveRunning)
	env.bindBob(t, runID)

	env.runner.Start()
	t.Cleanup(env.runner.Stop)
	env.runner.Kick()

	deadline := time.Now().Add(2 * time.Second)

	for time.Now().Before(deadline) {
		run, getErr := env.store.GetTestRun(t.Context(), runID)
		if getErr != nil {
			t.Fatalf("GetTestRun: %v", getErr)
		}

		if run.State == validatorcore.StateInviteMinted {
			return
		}

		time.Sleep(20 * time.Millisecond)
	}

	t.Fatal("kick did not mint the outgoing invite")
}

func TestRunner_PollMintsWithoutKick(t *testing.T) {
	t.Parallel()

	env := newRealInviteEnv(t)
	runID := "run-poll-mint"

	env.seedActive(t, runID, validatorcore.StateActiveRunning)
	env.bindBob(t, runID)

	fast, err := runner.New(runner.Deps{
		Store:         env.store,
		Invites:       env.svc,
		Parties:       env.parties,
		LocalIdentity: testLocalIdentity(),
		ProbeEmail:    testProbeEmail,
		ProbeName:     testProbeName,
		ProbeFilePath: createProbeFile(t),
		PollInterval:  20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}

	fast.BindOutgoing(env.out)
	fast.Start()
	t.Cleanup(fast.Stop)

	deadline := time.Now().Add(2 * time.Second)

	for time.Now().Before(deadline) {
		run, getErr := env.store.GetTestRun(t.Context(), runID)
		if getErr != nil {
			t.Fatalf("GetTestRun: %v", getErr)
		}

		if run.State == validatorcore.StateInviteMinted {
			return
		}

		time.Sleep(20 * time.Millisecond)
	}

	t.Fatal("poll did not mint the outgoing invite")
}

func TestRunner_NewRequiresDeps(t *testing.T) {
	t.Parallel()

	if _, err := runner.New(runner.Deps{}); err == nil {
		t.Fatal("expected error for empty deps")
	}
}
