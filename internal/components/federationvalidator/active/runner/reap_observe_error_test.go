// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package runner_test

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/runner"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestReapOnce_ObserveErrorIsLoggedAndRetried(t *testing.T) {
	t.Parallel()

	env := newStubEnv(t, nil, nil)
	runID := "run-watch-observe-err"
	env.seedActive(t, runID, validatorcore.StateReverseInviteAccepted)

	now := time.Unix(1_700_000_000, 0)

	var logs bytes.Buffer

	clocked, err := runner.New(runner.Deps{
		Store:               env.store,
		Invites:             env.invites,
		Parties:             env.parties,
		LocalIdentity:       testLocalIdentity(),
		ProbeEmail:          testProbeEmail,
		ProbeName:           testProbeName,
		ProbeFilePath:       createProbeFile(t),
		Log:                 slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		ReapIntervalSeconds: 3600,
		MaxDriveIdleSeconds: 10,
		Now:                 func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}

	clocked.BindOutgoing(env.out)
	t.Cleanup(clocked.Stop)

	aged := now.Unix() - 100
	env.ageUpdatedAt(t, runID, aged)

	injected := failNextTestRunFirst(t, env.store)

	clocked.ReapOnce()

	logged := logs.String()
	if !strings.Contains(logged, "active runner: observe session") {
		t.Fatalf("reap log missing observe error line: %q", logged)
	}

	if !strings.Contains(logged, injected.Error()) {
		t.Fatalf("reap log missing injected observe error: %q", logged)
	}

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	run, getErr := env.store.GetTestRun(t.Context(), runID)
	if getErr != nil {
		t.Fatalf("GetTestRun after observe error: %v", getErr)
	}

	if !run.IsActive {
		t.Fatal("observe error terminalized the idle run")
	}

	if run.TerminalReason != nil {
		t.Fatalf("terminal_reason = %v, want nil after observe error", run.TerminalReason)
	}

	if run.UpdatedAt != aged {
		t.Fatalf("updated_at = %d, want unchanged %d", run.UpdatedAt, aged)
	}

	clocked.ReapOnce()

	env.requireInactive(t, runID)
	env.requireState(t, runID, validatorcore.StateInterrupted)
	env.requireReason(t, runID, validatorcore.ReasonActiveDriveTimeout)
}

func failNextTestRunFirst(t *testing.T, store *validatorcore.Core) error {
	t.Helper()

	injected := errors.New("injected get test run failure")

	const cbName = "test_fail_get_test_run"

	var once sync.Once

	if err := store.DB().Callback().Query().Before("gorm:query").Register(cbName, func(db *gorm.DB) {
		if _, ok := db.Statement.Dest.(*validatorcore.TestRun); !ok {
			return
		}

		once.Do(func() {
			if addErr := db.AddError(injected); !errors.Is(addErr, injected) {
				t.Errorf("inject get test run failure: got %v", addErr)
			}
		})
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}

	t.Cleanup(func() {
		if err := store.DB().Callback().Query().Remove(cbName); err != nil {
			t.Errorf("remove callback: %v", err)
		}
	})

	return injected
}
