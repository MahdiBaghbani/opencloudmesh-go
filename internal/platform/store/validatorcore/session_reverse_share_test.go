// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"
)

func seedReverseShareRun(t *testing.T, core *Core, runID, state string, isActive bool, bobID *string) {
	t.Helper()

	now := time.Now().Unix()

	if err := core.DB().WithContext(t.Context()).Create(&TestRun{
		TestRunID:    runID,
		IsActive:     isActive,
		State:        state,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		BobUserID:    bobID,
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("seed run %s: %v", runID, err)
	}
}

func TestFindRunByRecipientAndTarget_ResolvesBobOnActiveRow(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	bob := "bob-user-1"
	seedReverseShareRun(t, core, "run-find-bob", StateCapabilityExercise, true, &bob)

	runID, err := core.FindRunByRecipientAndTarget(ctx, bob, "peer.example")
	if err != nil {
		t.Fatalf("FindRunByRecipientAndTarget: %v", err)
	}

	if runID != "run-find-bob" {
		t.Fatalf("run id = %q, want %q", runID, "run-find-bob")
	}
}

func TestFindRunByRecipientAndTarget_InactiveSafe(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	bob := "bob-user-inactive"
	seedReverseShareRun(t, core, "run-find-inactive", StateInterrupted, false, &bob)

	runID, err := core.FindRunByRecipientAndTarget(ctx, bob, "peer.example")
	if err != nil {
		t.Fatalf("FindRunByRecipientAndTarget on inactive row: %v", err)
	}

	if runID != "run-find-inactive" {
		t.Fatalf("run id = %q, want %q", runID, "run-find-inactive")
	}
}

func TestFindRunByRecipientAndTarget_UnknownRecipientOrHostMisses(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	bob := "bob-user-known"
	seedReverseShareRun(t, core, "run-find-miss", StateCapabilityExercise, true, &bob)

	cases := []struct {
		name      string
		recipient string
		host      string
	}{
		{"other recipient persists untouched", "alice-user", "peer.example"},
		{"other host never matches", bob, "other.example"},
		{"empty recipient", "", "peer.example"},
		{"empty host", bob, ""},
	}

	for _, tc := range cases {
		_, err := core.FindRunByRecipientAndTarget(ctx, tc.recipient, tc.host)
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("%s: error = %v, want gorm.ErrRecordNotFound", tc.name, err)
		}
	}
}

func TestFindRunByRecipientAndTarget_MultipleMatchesNeverArbitrary(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	// A reused recipient binding across two runs must not resolve to either
	// one; the caller gets not-found instead of an arbitrary row.
	shared := "bob-user-shared"
	seedReverseShareRun(t, core, "run-find-multi-1", StateInterrupted, false, &shared)
	seedReverseShareRun(t, core, "run-find-multi-2", StateInterrupted, false, &shared)

	_, err := core.FindRunByRecipientAndTarget(ctx, shared, "peer.example")
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("error = %v, want gorm.ErrRecordNotFound", err)
	}
}

func TestOpenReverseAwaitingShare_AdvancesFromCapabilityExercise(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	seedReverseShareRun(t, core, "run-open-wait", StateCapabilityExercise, true, nil)

	if err := core.OpenReverseAwaitingShare(ctx, "run-open-wait"); err != nil {
		t.Fatalf("OpenReverseAwaitingShare: %v", err)
	}

	got, err := core.GetTestRun(ctx, "run-open-wait")
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateReverseAwaitingShare {
		t.Fatalf("state = %q, want %q", got.State, StateReverseAwaitingShare)
	}

	if !got.IsActive {
		t.Fatal("is_active = 0, want the wait to keep the active lock")
	}
}

func TestOpenReverseAwaitingShare_MissesFromOtherStates(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	seedReverseShareRun(t, core, "run-open-miss", StateForwardShareSent, true, nil)

	if err := core.OpenReverseAwaitingShare(ctx, "run-open-miss"); !errors.Is(err, ErrStateTransitionMiss) {
		t.Fatalf("error = %v, want ErrStateTransitionMiss", err)
	}

	got, err := core.GetTestRun(ctx, "run-open-miss")
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.State != StateForwardShareSent {
		t.Fatalf("state = %q, want unchanged %q", got.State, StateForwardShareSent)
	}

	// A second open after the wait already opened is a miss, not a rewrite.
	if err := core.OpenReverseAwaitingShare(ctx, "run-open-miss"); !errors.Is(err, ErrStateTransitionMiss) {
		t.Fatalf("second open error = %v, want ErrStateTransitionMiss", err)
	}
}

func TestStampReverseShareProviderID_FirstWins(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	seedReverseShareRun(t, core, "run-stamp", StateTerminalPass, false, nil)

	if err := core.StampReverseShareProviderID(ctx, "run-stamp", "provider-1"); err != nil {
		t.Fatalf("first stamp: %v", err)
	}

	if err := core.StampReverseShareProviderID(ctx, "run-stamp", "provider-2"); err != nil {
		t.Fatalf("second stamp: %v", err)
	}

	got, err := core.GetTestRun(ctx, "run-stamp")
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if got.ReverseShareProviderID == nil || *got.ReverseShareProviderID != "provider-1" {
		t.Fatalf("reverse_share_provider_id = %v, want first-wins %q", got.ReverseShareProviderID, "provider-1")
	}
}

func TestStampReverseShareProviderID_RejectsEmptyProvider(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()

	seedReverseShareRun(t, core, "run-stamp-empty", StateTerminalPass, false, nil)

	if err := core.StampReverseShareProviderID(ctx, "run-stamp-empty", ""); err == nil {
		t.Fatal("empty provider id error = nil, want rejection")
	}
}
