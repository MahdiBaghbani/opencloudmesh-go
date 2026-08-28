// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseshare

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	fedcore "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/core"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/statistics"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestDriveReverseShareSuccess_EvidenceFailureBlocksTerminal(t *testing.T) {
	t.Parallel()

	env := newInternalEnv(t)
	_ = env.seedRun(t, "run-evidence-fail", validatorcore.StateReverseAwaitingShare)
	env.svc.shareReceived = func(context.Context, string) error {
		return errors.New("injected evidence failure")
	}

	err := env.svc.driveReverseShareSuccess(t.Context(), "run-evidence-fail", "provider-fail")
	if err == nil {
		t.Fatal("driveReverseShareSuccess error = nil, want evidence failure")
	}

	run := env.requireRun(t, "run-evidence-fail")
	if run.State != validatorcore.StateReverseAwaitingShare {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateReverseAwaitingShare)
	}

	if run.ReverseShareProviderID != nil {
		t.Fatalf("reverse_share_provider_id = %v, want nil", run.ReverseShareProviderID)
	}
}

type internalEnv struct {
	store *validatorcore.Core
	svc   *Service
}

func newInternalEnv(t *testing.T) *internalEnv {
	t.Helper()

	r, err := repos.New(t.Context(), config.PersistenceConfig{
		Backend: config.BackendSQLite,
		DataDir: t.TempDir(),
	})
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
		t.Fatalf("validatorcore.Attach: %v", err)
	}

	salt := make([]byte, statistics.RedactionSaltSize)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	hasher, err := fedcore.New(salt)
	if err != nil {
		t.Fatalf("fedcore.New: %v", err)
	}

	store.SetStatsHostHasher(hasher)

	svc, err := New(Deps{
		Store:          store,
		IncomingShares: r.IncomingShares,
		LocalIdentity:  localidentity.Identity{Scheme: "https"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return &internalEnv{store: store, svc: svc}
}

func (e *internalEnv) seedRun(t *testing.T, runID, state string) string {
	t.Helper()

	now := time.Now().Unix()
	bobID := uuid.NewString()

	if err := e.store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        state,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		BobUserID:    &bobID,
		OptInStats:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("seed run %s: %v", runID, err)
	}

	return bobID
}

func (e *internalEnv) requireRun(t *testing.T, runID string) *validatorcore.TestRun {
	t.Helper()

	run, err := e.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	return run
}
