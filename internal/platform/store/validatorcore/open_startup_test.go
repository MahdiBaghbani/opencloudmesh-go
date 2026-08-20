// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

// bootOrderIDs names the rows seeded for the boot-order pipeline test.
type bootOrderIDs struct {
	leftover    string
	passive     string
	permanent   string
	aged        string
	probePass   string
	probeUserID string
}

// TestStartupMaintenance_BootOrder exercises the full startup pipeline in one
// run and proves the ordering that matters: leftover active rows are
// interrupted with the startup-recovery reason before the stall sweep could
// ever see them, the expiry sweep only tombstones rows whose expiry was sealed
// before it ran, and the probe-linked pass row is kept for the harvest window.
func TestStartupMaintenance_BootOrder(t *testing.T) { //nolint:paralleltest // resets the process-local first-maintenance guard, which parallel tests must never observe mid-reset
	resetStartupFirstMaintenanceOnce(t)

	core := openTestCore(t)
	core.SetSessionConfig(SessionConfig{
		InFlightPassiveLimit:      10,
		CreatedTTLSeconds:         3600,
		PassiveRunningTTLSeconds:  3600,
		PassiveCompleteTTLSeconds: 3600,
		TerminalRetentionDays:     30,
		StallTimeoutSeconds:       3600,
	})

	now := time.Now().Unix()
	ids := seedBootOrderRows(t, core, now)

	if err := core.startupMaintenance(t.Context()); err != nil {
		t.Fatalf("startupMaintenance: %v", err)
	}

	assertBootOrderLeftoverInterrupted(t, core, ids.leftover, now)
	assertBootOrderPassiveExpired(t, core, ids.passive)
	assertBootOrderPermanentTombstoned(t, core, ids.permanent)
	assertRunHardDeleted(t, core, core.DB(), ids.aged)
	assertBootOrderProbePassKept(t, core, ids.probePass, ids.probeUserID)
}

// seedBootOrderRows plants one row per pipeline stage. The single active row
// is stale enough for the stall sweep to claim it and permanent-opted with a
// finite tier, so both orderings are observable: the recovery reason proves
// recovery ran before the sweep, and the future expires_at seal proves
// recovery ran before the tombstone stage.
func seedBootOrderRows(t *testing.T, core *Core, now int64) bootOrderIDs {
	t.Helper()

	ids := bootOrderIDs{
		leftover:    "run-boot-leftover",
		passive:     "run-boot-passive-created",
		permanent:   "run-boot-permanent-expired",
		aged:        "run-boot-aged-terminal",
		probePass:   "run-boot-probe-pass",
		probeUserID: "018f3c7a-9c2e-7b1d-8f4a-2e6c1d9a5b30",
	}

	stale := now - 2*3600
	agedFinished := now - int64(60*24*3600)
	recentFinished := now - 3600
	pastExpiry := now - 600
	tier30 := RetentionTier30

	rows := []*TestRun{
		{
			TestRunID:      ids.leftover,
			IsActive:       true,
			State:          StateActiveRunning,
			SessionKind:    SessionKindActiveFull,
			TargetHost:     "boot.example",
			OptInPermanent: true,
			RetentionTier:  &tier30,
			CreatedAt:      stale,
			UpdatedAt:      stale,
		},
		{
			TestRunID:   ids.passive,
			IsActive:    false,
			State:       StateCreated,
			SessionKind: SessionKindPassiveOnly,
			TargetHost:  "boot.example",
			CreatedAt:   stale,
			UpdatedAt:   stale,
		},
		{
			TestRunID:      ids.permanent,
			IsActive:       false,
			State:          StateTerminalFail,
			SessionKind:    SessionKindPassiveOnly,
			TargetHost:     "boot.example",
			FinishedAt:     &agedFinished,
			OptInPermanent: true,
			ExpiresAt:      &pastExpiry,
			CreatedAt:      agedFinished,
			UpdatedAt:      agedFinished,
		},
		{
			TestRunID:   ids.aged,
			IsActive:    false,
			State:       StateTerminalFail,
			SessionKind: SessionKindPassiveOnly,
			TargetHost:  "boot.example",
			FinishedAt:  &agedFinished,
			CreatedAt:   agedFinished,
			UpdatedAt:   agedFinished,
		},
		{
			TestRunID:   ids.probePass,
			IsActive:    false,
			State:       StateTerminalPass,
			SessionKind: SessionKindActiveFull,
			TargetHost:  "boot.example",
			BobUserID:   &ids.probeUserID,
			FinishedAt:  &recentFinished,
			CreatedAt:   recentFinished,
			UpdatedAt:   recentFinished,
		},
	}

	for _, row := range rows {
		if err := core.DB().Create(row).Error; err != nil {
			t.Fatalf("seed %s: %v", row.TestRunID, err)
		}
	}

	seedRunChildSet(t, core.DB(), ids.aged)

	return ids
}

// assertBootOrderLeftoverInterrupted proves startup recovery ran first: the
// reason is the recovery reason (a stall reason would mean the sweep won),
// and the freshly sealed future expiry kept the row out of the tombstone
// stage in the same pass.
func assertBootOrderLeftoverInterrupted(t *testing.T, core *Core, id string, now int64) {
	t.Helper()

	got, err := core.GetTestRun(t.Context(), id)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v", id, err)
	}

	if got.IsActive || got.State != StateInterrupted {
		t.Fatalf("leftover is_active=%v state=%q, want interrupted inactive", got.IsActive, got.State)
	}

	if got.TerminalReason == nil || *got.TerminalReason != "startup_unrecoverable_active" {
		t.Fatalf(
			"leftover terminal_reason = %v, want %q (a stall reason means the sweep ran before recovery)",
			got.TerminalReason,
			"startup_unrecoverable_active",
		)
	}

	if got.ExpiresAt == nil || *got.ExpiresAt <= now {
		t.Fatalf("leftover expires_at = %v, want a future seal from the recovery pass", got.ExpiresAt)
	}

	if got.HarvestedAt != nil || got.HarvestReason != nil {
		t.Fatalf(
			"leftover harvest markers = (%v, %v), want both nil (tombstone sweep must not touch a freshly sealed row)",
			got.HarvestedAt,
			got.HarvestReason,
		)
	}
}

// assertBootOrderPassiveExpired proves the passive TTL stage terminalized the
// expired created row.
func assertBootOrderPassiveExpired(t *testing.T, core *Core, id string) {
	t.Helper()

	got, err := core.GetTestRun(t.Context(), id)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v", id, err)
	}

	if got.State != StateTerminalFail {
		t.Fatalf("passive state = %q, want %q", got.State, StateTerminalFail)
	}

	if got.TerminalReason == nil || *got.TerminalReason != "created_ttl_expired" {
		t.Fatalf("passive terminal_reason = %v, want %q", got.TerminalReason, "created_ttl_expired")
	}
}

// assertBootOrderPermanentTombstoned proves the retention sweep tombstoned
// the expired permanent report instead of deleting it.
func assertBootOrderPermanentTombstoned(t *testing.T, core *Core, id string) {
	t.Helper()

	got, err := core.GetTestRun(t.Context(), id)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v", id, err)
	}

	if got.HarvestedAt == nil {
		t.Fatal("expired permanent row harvested_at = nil, want tombstoned")
	}

	if got.HarvestReason == nil || *got.HarvestReason != HarvestReasonExpired {
		t.Fatalf("permanent harvest_reason = %v, want %q", got.HarvestReason, HarvestReasonExpired)
	}
}

// assertBootOrderProbePassKept proves every startup stage kept the
// probe-linked pass row and its probe link untouched until retention prune.
func assertBootOrderProbePassKept(t *testing.T, core *Core, id, probeUserID string) {
	t.Helper()

	got, err := core.GetTestRun(t.Context(), id)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v (probe-linked pass must survive startup)", id, err)
	}

	if got.State != StateTerminalPass {
		t.Fatalf("probe pass state = %q, want unchanged %q", got.State, StateTerminalPass)
	}

	if got.BobUserID == nil || *got.BobUserID != probeUserID {
		t.Fatalf("probe pass bob_user_id = %v, want preserved %q", got.BobUserID, probeUserID)
	}

	if got.HarvestedAt != nil || got.HarvestReason != nil {
		t.Fatalf("probe pass harvest markers = (%v, %v), want both nil", got.HarvestedAt, got.HarvestReason)
	}
}

func TestStartupMaintenance_StallSweepPrecedesPermanentExpiry(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	core.SetSessionConfig(SessionConfig{
		InFlightPassiveLimit:      10,
		CreatedTTLSeconds:         3600,
		PassiveRunningTTLSeconds:  3600,
		PassiveCompleteTTLSeconds: 3600,
		TerminalRetentionDays:     30,
		StallTimeoutSeconds:       3600,
	})

	ctx := t.Context()
	now := time.Now().Unix()
	finishedAt := now - int64(60*24*3600)
	tier30 := RetentionTier30

	// A permanent terminal hybrid: the row holds a terminal state but still
	// keeps the active lock, and expires_at was never sealed. Only the stall
	// sweep's lock-clearing reconciliation seals expires_at; the expiry sweep
	// can tombstone the row in the same boot only if the sweep ran first.
	// Startup recovery skips the row because its state is already terminal.
	hybridID := "run-boot-hybrid-permanent"

	if err := core.DB().WithContext(ctx).Create(&TestRun{
		TestRunID:      hybridID,
		IsActive:       true,
		State:          StateTerminalFail,
		SessionKind:    SessionKindActiveFull,
		TargetHost:     "boot.example",
		FinishedAt:     &finishedAt,
		OptInPermanent: true,
		RetentionTier:  &tier30,
		CreatedAt:      finishedAt,
		UpdatedAt:      finishedAt,
	}).Error; err != nil {
		t.Fatalf("seed permanent hybrid row: %v", err)
	}

	// The full first-maintenance chain runs directly: the process-local guard
	// would make a gated call nondeterministic under parallel tests, and this
	// test needs the stall sweep to run on every execution.
	if err := core.firstStartupMaintenance(ctx); err != nil {
		t.Fatalf("firstStartupMaintenance: %v", err)
	}

	got, err := core.GetTestRun(ctx, hybridID)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v (permanent rows are tombstoned, never deleted)", hybridID, err)
	}

	if got.IsActive {
		t.Fatal("hybrid is_active = 1, want 0 after lock-clearing reconciliation")
	}

	wantExpires := finishedAt + 30*SecondsPerDay

	if got.ExpiresAt == nil || *got.ExpiresAt != wantExpires {
		t.Fatalf("hybrid expires_at = %v, want sealed %d", got.ExpiresAt, wantExpires)
	}

	if got.HarvestedAt == nil {
		t.Fatal("hybrid harvested_at = nil, want tombstoned (the sweep sealed an already-past expiry)")
	}

	if got.HarvestReason == nil || *got.HarvestReason != HarvestReasonExpired {
		t.Fatalf("hybrid harvest_reason = %v, want %q", got.HarvestReason, HarvestReasonExpired)
	}
}
