// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package runner_test

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/runner"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestSupervisor_PostDriveObserveErrorIsLoggedAndRetried(t *testing.T) {
	t.Parallel()

	invites := newGatedInvites()
	env := newStubEnv(t, invites, nil)
	runID := "run-supervisor-observe-err"

	env.seedActive(t, runID, validatorcore.StateActiveRunning)
	env.bindBob(t, runID)

	aged := time.Now().Unix() - 3600
	env.ageUpdatedAt(t, runID, aged)

	var logs lockedBuffer

	logged, err := runner.New(runner.Deps{
		Store:               env.store,
		Invites:             invites,
		Parties:             env.parties,
		LocalIdentity:       testLocalIdentity(),
		ProbeEmail:          testProbeEmail,
		ProbeName:           testProbeName,
		ProbeFilePath:       createProbeFile(t),
		Log:                 slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		ReapIntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}

	logged.BindOutgoing(env.out)
	t.Cleanup(func() {
		invites.release()
		logged.Stop()
	})

	logged.Start()

	select {
	case <-invites.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor never reached drive work")
	}

	injected := failNextTestRunFirst(t, env.store)

	invites.release()

	waitForLogContains(t, &logs, injected.Error())

	loggedText := logs.String()
	if !strings.Contains(loggedText, "active runner: observe session") {
		t.Fatalf("supervisor log missing observe error line: %q", loggedText)
	}

	requireActiveUnchanged(t, env, runID, aged)

	if got := invites.calls.Load(); got != 1 {
		t.Fatalf("mints after observe error = %d, want 1", got)
	}

	logged.Kick()
	waitForMintCalls(t, &invites.calls, 2)

	requireActiveUnchanged(t, env, runID, aged)
}

type gatedInvites struct {
	entered     chan struct{}
	proceed     chan struct{}
	gate        sync.Once
	releaseOnce sync.Once
	calls       atomic.Int32
}

func newGatedInvites() *gatedInvites {
	return &gatedInvites{
		entered: make(chan struct{}),
		proceed: make(chan struct{}),
	}
}

func (s *gatedInvites) MintOutgoingInvite(ctx context.Context, testRunID string) (*invitesoutgoing.OutgoingInvite, error) {
	s.gate.Do(func() {
		close(s.entered)
	})

	select {
	case <-s.proceed:
	case <-ctx.Done():
		return nil, fmt.Errorf("gated mint: %w", ctx.Err())
	}

	s.calls.Add(1)

	return &invitesoutgoing.OutgoingInvite{ID: "invite-" + testRunID, Token: "tok-" + testRunID}, nil
}

func (s *gatedInvites) SolicitReverse(context.Context, string) error {
	return nil
}

func (s *gatedInvites) release() {
	s.releaseOnce.Do(func() {
		close(s.proceed)
	})
}

func waitForMintCalls(t *testing.T, calls *atomic.Int32, want int32) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)

	for time.Now().Before(deadline) {
		if calls.Load() >= want {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("mints = %d, want %d", calls.Load(), want)
}
