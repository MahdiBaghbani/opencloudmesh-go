// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package runner_test

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/runner"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestDriveOnce_ListActiveErrorIsLoggedWithoutSideEffects(t *testing.T) {
	t.Parallel()

	env := newStubEnv(t, nil, nil)
	runID := "run-list-active-driveonce"
	waiterID := "run-list-active-waiter"

	env.seedActive(t, runID, validatorcore.StateActiveRunning)
	env.bindBob(t, runID)

	aged := time.Now().Unix() - 3600
	env.ageUpdatedAt(t, runID, aged)
	seedReadyWaiter(t, env.store, waiterID, aged)

	var logs lockedBuffer

	logged, err := runner.New(runner.Deps{
		Store:               env.store,
		Invites:             env.invites,
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
	t.Cleanup(logged.Stop)

	injected := failNextListActive(t, env.store)

	logged.DriveOnce(t.Context())

	requireListActiveFailureLogged(t, logs.String(), injected)
	requireActiveUnchanged(t, env, runID, aged)

	waiter, getErr := env.store.GetTestRun(t.Context(), waiterID)
	if getErr != nil {
		t.Fatalf("GetTestRun waiter: %v", getErr)
	}

	if waiter.IsActive || waiter.State != validatorcore.StatePassiveRunning {
		t.Fatalf("waiter is_active=%v state=%q, want passive_running", waiter.IsActive, waiter.State)
	}

	if env.invites.mints != 0 || env.invites.solicits != 0 || env.out.calls != 0 {
		t.Fatalf("list-active failure drove work: mints=%d solicits=%d creates=%d", env.invites.mints, env.invites.solicits, env.out.calls)
	}
}

func TestSupervisor_ListActiveErrorIsLoggedWithoutSideEffects(t *testing.T) {
	t.Parallel()

	env := newStubEnv(t, nil, nil)
	runID := "run-list-active-supervisor"

	env.seedActive(t, runID, validatorcore.StateActiveRunning)
	env.bindBob(t, runID)

	aged := time.Now().Unix() - 3600
	env.ageUpdatedAt(t, runID, aged)

	var logs lockedBuffer

	logged, err := runner.New(runner.Deps{
		Store:               env.store,
		Invites:             env.invites,
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

	injected := failNextListActive(t, env.store)

	logged.Start()
	t.Cleanup(logged.Stop)

	waitForLogContains(t, &logs, injected.Error())
	requireListActiveFailureLogged(t, logs.String(), injected)
	requireActiveUnchanged(t, env, runID, aged)

	if env.invites.mints != 0 || env.invites.solicits != 0 || env.out.calls != 0 {
		t.Fatalf("list-active failure drove work: mints=%d solicits=%d creates=%d", env.invites.mints, env.invites.solicits, env.out.calls)
	}
}

func requireListActiveFailureLogged(t *testing.T, logged string, injected error) {
	t.Helper()

	if !strings.Contains(logged, "active runner: list active runs") {
		t.Fatalf("log missing list-active error line: %q", logged)
	}

	if !strings.Contains(logged, injected.Error()) {
		t.Fatalf("log missing injected list-active error: %q", logged)
	}
}

func requireActiveUnchanged(t *testing.T, env *testEnv, runID string, wantUpdatedAt int64) {
	t.Helper()

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != validatorcore.StateActiveRunning {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateActiveRunning)
	}

	if !run.IsActive {
		t.Fatal("injected store error terminalized the run")
	}

	if run.TerminalReason != nil {
		t.Fatalf("terminal_reason = %v, want nil", run.TerminalReason)
	}

	if run.UpdatedAt != wantUpdatedAt {
		t.Fatalf("updated_at = %d, want unchanged %d", run.UpdatedAt, wantUpdatedAt)
	}
}

func waitForLogContains(t *testing.T, logs *lockedBuffer, needle string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)

	for time.Now().Before(deadline) {
		if strings.Contains(logs.String(), needle) {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("log missing %q: %q", needle, logs.String())
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	n, err := b.buf.Write(p)
	if err != nil {
		return n, fmt.Errorf("log buffer: %w", err)
	}

	return n, nil
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

func failNextListActive(t *testing.T, store *validatorcore.Core) error {
	t.Helper()

	injected := errors.New("injected list active failure")

	const cbName = "test_fail_list_active"

	var once sync.Once

	if err := store.DB().Callback().Query().Before("gorm:query").Register(cbName, func(db *gorm.DB) {
		if !isListActiveDest(db.Statement.Dest) {
			return
		}

		once.Do(func() {
			if addErr := db.AddError(injected); !errors.Is(addErr, injected) {
				t.Errorf("inject list active failure: got %v", addErr)
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

func isListActiveDest(dest any) bool {
	switch dest.(type) {
	case *[]*validatorcore.TestRun, *[]validatorcore.TestRun:
		return true
	default:
		return false
	}
}
