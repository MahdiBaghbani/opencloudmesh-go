// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package runner_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/runner"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func newClockedRunner(
	t *testing.T,
	env *testEnv,
	out runner.OutgoingCreator,
	now *time.Time,
	maxAttempts int,
	idleSeconds int,
) *runner.Runner {
	t.Helper()

	var invites runner.InviteDriver
	if env.invites != nil {
		invites = env.invites
	} else {
		invites = env.svc
	}

	clocked, err := runner.New(runner.Deps{
		Store:               env.store,
		Invites:             invites,
		Parties:             env.parties,
		LocalIdentity:       testLocalIdentity(),
		ProbeEmail:          testProbeEmail,
		ProbeName:           testProbeName,
		ProbeFilePath:       createProbeFile(t),
		ReapIntervalSeconds: 3600,
		MaxDriveIdleSeconds: idleSeconds,
		MaxDispatchAttempts: maxAttempts,
		BackoffBaseSeconds:  1,
		BackoffCapSeconds:   60,
		Now:                 func() time.Time { return *now },
	})
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}

	clocked.BindOutgoing(out)

	return clocked
}

func failNextTestRunUpdate(t *testing.T, store *validatorcore.Core) {
	t.Helper()

	const cbName = "test_fail_hardfail_update"

	injected := errors.New("injected hard-fail persist failure")

	var once sync.Once

	if err := store.DB().Callback().Update().Before("gorm:update").Register(cbName, func(db *gorm.DB) {
		if db.Statement.Table != "test_run" {
			if _, ok := db.Statement.Dest.(*validatorcore.TestRun); !ok {
				if _, ok := db.Statement.Model.(*validatorcore.TestRun); !ok {
					return
				}
			}
		}

		once.Do(func() {
			if addErr := db.AddError(injected); !errors.Is(addErr, injected) {
				t.Errorf("inject hard-fail persist failure: got %v", addErr)
			}
		})
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}

	t.Cleanup(func() {
		if err := store.DB().Callback().Update().Remove(cbName); err != nil {
			t.Errorf("remove callback: %v", err)
		}
	})
}
