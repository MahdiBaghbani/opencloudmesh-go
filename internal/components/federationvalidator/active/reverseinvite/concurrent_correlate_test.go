// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/runner"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestConcurrentCorrelate_ActiveSessionsStayKeyed(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()

	env.seedRunAt(t, "run-alpha", validatorcore.StateActiveRunning, "alpha.example", nil)
	env.seedRunAt(t, "run-beta", validatorcore.StateActiveRunning, "beta.example", nil)

	inviteA, err := env.svc.MintOutgoingInvite(ctx, "run-alpha")
	if err != nil {
		t.Fatalf("mint alpha: %v", err)
	}

	inviteB, err := env.svc.MintOutgoingInvite(ctx, "run-beta")
	if err != nil {
		t.Fatalf("mint beta: %v", err)
	}

	handler := env.inviteAcceptedEndpoint()

	var wg sync.WaitGroup

	start := make(chan struct{})
	codes := make(chan int, 2)

	wg.Add(2)

	go func() {
		defer wg.Done()

		<-start

		codes <- postInviteAccepted(t, handler, inviteA.Token, "alpha.example").Code
	}()
	go func() {
		defer wg.Done()

		<-start

		codes <- postInviteAccepted(t, handler, inviteB.Token, "beta.example").Code
	}()

	close(start)
	wg.Wait()
	close(codes)

	for code := range codes {
		if code != 200 {
			t.Fatalf("invite-accepted status = %d, want 200", code)
		}
	}

	env.requireState(t, "run-alpha", validatorcore.StateInviteAccepted)
	env.requireState(t, "run-beta", validatorcore.StateInviteAccepted)

	alpha, err := env.store.GetTestRun(ctx, "run-alpha")
	if err != nil {
		t.Fatalf("GetTestRun alpha: %v", err)
	}

	beta, err := env.store.GetTestRun(ctx, "run-beta")
	if err != nil {
		t.Fatalf("GetTestRun beta: %v", err)
	}

	if alpha.OutgoingInviteID == nil || *alpha.OutgoingInviteID != inviteA.ID {
		t.Fatalf("alpha outgoing_invite_id = %v, want %q", alpha.OutgoingInviteID, inviteA.ID)
	}

	if beta.OutgoingInviteID == nil || *beta.OutgoingInviteID != inviteB.ID {
		t.Fatalf("beta outgoing_invite_id = %v, want %q", beta.OutgoingInviteID, inviteB.ID)
	}

	if alpha.DesignatedShareWith == nil || *alpha.DesignatedShareWith != "accepter-user" {
		t.Fatalf("alpha designated_share_with = %v", alpha.DesignatedShareWith)
	}

	if beta.DesignatedShareWith == nil || *beta.DesignatedShareWith != "accepter-user" {
		t.Fatalf("beta designated_share_with = %v", beta.DesignatedShareWith)
	}
}

func TestConcurrentCorrelate_LookupMissSkipsSafely(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()

	env.seedRunAt(t, "run-live", validatorcore.StateActiveRunning, "live.example", nil)
	env.seedRunAt(t, "run-other", validatorcore.StateActiveRunning, "other.example", nil)

	live, err := env.svc.MintOutgoingInvite(ctx, "run-live")
	if err != nil {
		t.Fatalf("mint live: %v", err)
	}

	if _, mintErr := env.svc.MintOutgoingInvite(ctx, "run-other"); mintErr != nil {
		t.Fatalf("mint other: %v", mintErr)
	}

	handler := env.inviteAcceptedEndpoint()

	unbound := &invitesoutgoing.OutgoingInvite{
		Token:           "unbound-token",
		ProviderFQDN:    testLocalDomain,
		CreatedByUserID: "run-live",
		CreatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(time.Hour),
		Status:          invites.InviteStatusPending,
	}
	if createErr := env.outgoing.Create(ctx, unbound); createErr != nil {
		t.Fatalf("create unbound invite: %v", createErr)
	}

	var wg sync.WaitGroup

	start := make(chan struct{})

	wg.Add(2)

	go func() {
		defer wg.Done()

		<-start

		_ = postInviteAccepted(t, handler, "missing-token", "live.example")
	}()
	go func() {
		defer wg.Done()

		<-start

		_ = postInviteAccepted(t, handler, unbound.Token, "live.example")
	}()

	close(start)
	wg.Wait()

	env.requireState(t, "run-live", validatorcore.StateInviteMinted)
	env.requireState(t, "run-other", validatorcore.StateInviteMinted)

	got, err := env.store.FindRunByOutgoingInviteID(ctx, live.ID)
	if err != nil {
		t.Fatalf("FindRunByOutgoingInviteID: %v", err)
	}

	if got != "run-live" {
		t.Fatalf("bound invite resolved %q, want run-live", got)
	}

	if _, err := env.store.FindRunByOutgoingInviteID(ctx, unbound.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("FindRunByOutgoingInviteID unbound: %v, want ErrRecordNotFound", err)
	}
}

func TestRunnerPath_ListActiveGetTestRunMintsEachRun(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()

	env.seedRunAt(t, "run-alpha", validatorcore.StateActiveRunning, "alpha.example", nil)
	env.seedRunAt(t, "run-beta", validatorcore.StateActiveRunning, "beta.example", nil)
	bindBobIDOnly(t, env, "run-alpha")
	bindBobIDOnly(t, env, "run-beta")

	active, err := runner.New(runner.Deps{
		Store:               env.store,
		Invites:             env.svc,
		Parties:             env.parties,
		LocalIdentity:       testLocalIdentity(),
		ProbeEmail:          "probe@localhost",
		ProbeName:           "Probe User",
		ProbeFilePath:       "probe.txt",
		ReapIntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}

	active.DriveOnce(ctx)

	for _, id := range []string{"run-alpha", "run-beta"} {
		env.requireState(t, id, validatorcore.StateInviteMinted)

		run, getErr := env.store.GetTestRun(ctx, id)
		if getErr != nil {
			t.Fatalf("GetTestRun %s: %v", id, getErr)
		}

		if run.OutgoingInviteID == nil || *run.OutgoingInviteID == "" {
			t.Fatalf("%s outgoing_invite_id empty after ListActive/GetTestRun mint", id)
		}

		resolved, findErr := env.store.FindRunByOutgoingInviteID(ctx, *run.OutgoingInviteID)
		if findErr != nil {
			t.Fatalf("FindRunByOutgoingInviteID %s: %v", id, findErr)
		}

		if resolved != id {
			t.Fatalf("invite for %s resolved %q", id, resolved)
		}
	}

	rows, err := env.store.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}

	if len(rows) != 2 {
		t.Fatalf("ListActive count = %d, want 2", len(rows))
	}
}

func bindBobIDOnly(t *testing.T, env *testEnv, runID string) {
	t.Helper()

	if err := env.store.DB().WithContext(t.Context()).Model(&validatorcore.TestRun{}).
		Where("test_run_id = ?", runID).
		Update("bob_user_id", "bob-"+runID).Error; err != nil {
		t.Fatalf("bind bob id: %v", err)
	}
}
