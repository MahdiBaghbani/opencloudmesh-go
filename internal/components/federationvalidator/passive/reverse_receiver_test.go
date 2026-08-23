// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"errors"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestProbeRunner_PromoteMaterializesReverseReceiver(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	parties := identity.NewMemoryPartyRepo()
	h := NewHandler(store, nil)
	h.SetReverseReceiver(
		parties,
		"local.example",
		config.DefaultValidatorProbeEmail,
		config.DefaultValidatorProbeDisplayName,
	)

	ctx := t.Context()
	runID := "run-promote-bob"

	createCreatedRun(t, store, runID, "https://peer.example", true, false)
	h.probe.run(ctx, runID)

	run, err := store.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if !run.IsActive || run.State != validatorcore.StateActiveRunning {
		t.Fatalf("is_active=%v state=%q, want active_running", run.IsActive, run.State)
	}

	if run.BobUserID == nil || *run.BobUserID == "" {
		t.Fatal("bob_user_id is empty after promotion")
	}

	bob, err := parties.Get(ctx, *run.BobUserID)
	if err != nil {
		t.Fatalf("Get bob party: %v", err)
	}

	if bob.ID != *run.BobUserID {
		t.Fatalf("bob id = %q, want %q", bob.ID, *run.BobUserID)
	}

	if bob.DisplayName != config.DefaultValidatorProbeDisplayName {
		t.Fatalf("bob display name = %q", bob.DisplayName)
	}

	if bob.Role != identity.RoleProbe || bob.ExpiresAt != nil {
		t.Fatalf("bob party = %+v", bob)
	}

	if _, err := parties.Get(ctx, runID); !errors.Is(err, identity.ErrUserNotFound) {
		t.Fatalf("alice must not be created at promote, err=%v", err)
	}
}
