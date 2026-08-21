// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestSweepExpiredPermanentReports_HardExpiryWipesAndKeepsParent(t *testing.T) {
	t.Parallel()

	sqlCore := openPeerStore(t)

	core, attachErr := Attach(sqlCore.DB(), DefaultSessionConfig())
	if attachErr != nil {
		t.Fatalf("Attach: %v", attachErr)
	}

	db := core.DB()
	ctx := t.Context()
	now := time.Now().Unix()
	finished := now - int64(40*24*3600)
	expires := now - 60

	seedExpiredPermanentRun(t, db, ctx, "run-hard-expiry", finished, expires)
	seedExpiryChildRows(t, db, "run-hard-expiry")

	pass := GradePass
	if err := core.InsertStatsRaw(ctx, &StatsRaw{
		K:              "k-hard-expiry-stats",
		HostHash:       "hash-hard-expiry",
		SessionKind:    SessionKindPassiveOnly,
		Platform:       "Keep",
		GradeDiscovery: &pass,
		CreatedAt:      now,
	}); err != nil {
		t.Fatalf("insert stats_raw: %v", err)
	}

	if err := core.SweepExpiredPermanentReports(ctx); err != nil {
		t.Fatalf("SweepExpiredPermanentReports: %v", err)
	}

	got, err := core.GetTestRun(ctx, "run-hard-expiry")
	if err != nil {
		t.Fatalf("GetTestRun: %v (parent must survive as a tombstone)", err)
	}

	assertHardExpiryTombstone(t, got)
	assertOutgoingInviteReusableAfterTombstone(t, db, ctx, "run-hard-expiry", now)
	assertChildRowCount(t, db, "report_exchange", "run-hard-expiry", 0)
	assertChildRowCount(t, db, "evidence_row", "run-hard-expiry", 0)
	assertChildRowCount(t, db, "dispatch_reservation", "run-hard-expiry", 0)
	assertChildRowCount(t, db, "share_correlation", "run-hard-expiry", 0)
	assertStatsRawCount(t, db, ctx, 1)
}

func TestStartRetentionSweep_StopsOnCancel(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})

	go func() {
		core.StartRetentionSweep(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartRetentionSweep did not return after cancel")
	}
}

func TestSweepExpiredPermanentReports_SkipsGuardedRows(t *testing.T) {
	t.Parallel()

	sqlCore := openPeerStore(t)

	core, attachErr := Attach(sqlCore.DB(), DefaultSessionConfig())
	if attachErr != nil {
		t.Fatalf("Attach: %v", attachErr)
	}

	db := core.DB()
	ctx := t.Context()
	now := time.Now().Unix()
	finished := now - int64(40*24*3600)
	expires := now - 60
	knownHarvested := now - int64(10*24*3600)
	activeID := "run-guard-active"
	nonPermanentID := "run-guard-nonpermanent"
	harvestedID := "run-guard-harvested"
	nullExpiresID := "run-guard-nullexpires"

	seedExpiredPermanentRun(t, db, ctx, activeID, finished, expires)
	seedExpiredPermanentRun(t, db, ctx, nonPermanentID, finished, expires)
	seedExpiredPermanentRun(t, db, ctx, harvestedID, finished, expires)
	seedExpiredPermanentRun(t, db, ctx, nullExpiresID, finished, expires)
	seedExpiryChildRows(t, db, activeID)
	seedExpiryChildRows(t, db, nonPermanentID)
	seedExpiryChildRows(t, db, harvestedID)
	seedExpiryChildRows(t, db, nullExpiresID)

	mustExec(t, db, "UPDATE test_run SET is_active = 1 WHERE test_run_id = '"+activeID+"'")
	mustExec(t, db, "UPDATE test_run SET opt_in_permanent = 0 WHERE test_run_id = '"+nonPermanentID+"'")
	mustExec(t, db, fmt.Sprintf(
		"UPDATE test_run SET harvested_at = %d, harvest_reason = '%s' WHERE test_run_id = '%s'",
		knownHarvested,
		HarvestReasonExpired,
		harvestedID,
	))
	mustExec(t, db, "UPDATE test_run SET expires_at = NULL WHERE test_run_id = '"+nullExpiresID+"'")

	if err := core.SweepExpiredPermanentReports(ctx); err != nil {
		t.Fatalf("SweepExpiredPermanentReports: %v", err)
	}

	assertSweepGuardUnchanged(t, core, db, activeID)
	assertSweepGuardUnchanged(t, core, db, nonPermanentID)
	assertSweepGuardUnchanged(t, core, db, harvestedID)
	assertSweepGuardUnchanged(t, core, db, nullExpiresID)

	active, err := core.GetTestRun(ctx, activeID)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v", activeID, err)
	}

	if !active.IsActive || active.HarvestedAt != nil {
		t.Fatalf("%s is_active=%v harvested_at=%v, want active unswept", activeID, active.IsActive, active.HarvestedAt)
	}

	nonPermanent, err := core.GetTestRun(ctx, nonPermanentID)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v", nonPermanentID, err)
	}

	if nonPermanent.OptInPermanent || nonPermanent.HarvestedAt != nil {
		t.Fatalf(
			"%s opt_in_permanent=%v harvested_at=%v, want non-permanent unswept",
			nonPermanentID,
			nonPermanent.OptInPermanent,
			nonPermanent.HarvestedAt,
		)
	}

	harvested, err := core.GetTestRun(ctx, harvestedID)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v", harvestedID, err)
	}

	if harvested.HarvestedAt == nil || *harvested.HarvestedAt != knownHarvested {
		t.Fatalf("%s harvested_at = %v, want unchanged %d", harvestedID, harvested.HarvestedAt, knownHarvested)
	}

	nullExpires, err := core.GetTestRun(ctx, nullExpiresID)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v", nullExpiresID, err)
	}

	if nullExpires.ExpiresAt != nil || nullExpires.HarvestedAt != nil {
		t.Fatalf(
			"%s expires_at=%v harvested_at=%v, want NULL expires unswept",
			nullExpiresID,
			nullExpires.ExpiresAt,
			nullExpires.HarvestedAt,
		)
	}
}

func assertSweepGuardUnchanged(t *testing.T, core *Core, db *gorm.DB, id string) {
	t.Helper()

	got, err := core.GetTestRun(t.Context(), id)
	if err != nil {
		t.Fatalf("GetTestRun %s: %v (guarded row must remain)", id, err)
	}

	if got.TargetOrigin != "https://pii.example" {
		t.Fatalf("%s target_origin = %q, want original PII", id, got.TargetOrigin)
	}

	wantInvite := seedOutgoingInviteID(id)
	if got.OutgoingInviteID == nil || *got.OutgoingInviteID != wantInvite {
		t.Fatalf("%s outgoing_invite_id = %v, want %q", id, got.OutgoingInviteID, wantInvite)
	}

	assertChildRowCount(t, db, "report_exchange", id, 1)
	assertChildRowCount(t, db, "evidence_row", id, 1)
	assertChildRowCount(t, db, "dispatch_reservation", id, 1)
	assertChildRowCount(t, db, "share_correlation", id, 1)
}

func assertHardExpiryTombstone(t *testing.T, got *TestRun) {
	t.Helper()

	if got.HarvestReason == nil || *got.HarvestReason != HarvestReasonExpired {
		t.Fatalf("harvest_reason = %v, want %q", got.HarvestReason, HarvestReasonExpired)
	}

	if got.HarvestedAt == nil {
		t.Fatal("harvested_at is NULL, want stamped")
	}

	if got.IsActive {
		t.Fatal("is_active = 1, want 0")
	}

	if !got.OptInPermanent {
		t.Fatal("opt_in_permanent cleared, want retained")
	}

	assertWipedPermanentPII(t, got)
}

func assertWipedPermanentPII(t *testing.T, got *TestRun) {
	t.Helper()

	assertWipedPermanentContactPII(t, got)
	assertWipedPermanentIdentityPII(t, got)

	if !got.OptInActive {
		t.Fatal("opt_in_active cleared, want retained")
	}
}

func assertWipedPermanentContactPII(t *testing.T, got *TestRun) {
	t.Helper()

	if got.TargetOrigin != "" {
		t.Fatalf("target_origin = %q, want empty", got.TargetOrigin)
	}

	if got.TargetHost != "" {
		t.Fatalf("target_host = %q, want empty", got.TargetHost)
	}

	if got.DiscoveryURL != "" {
		t.Fatalf("discovery_url = %q, want empty", got.DiscoveryURL)
	}

	if got.JwksURI != "" {
		t.Fatalf("jwks_uri = %q, want empty", got.JwksURI)
	}

	if got.ManifestJSON != nil {
		t.Fatalf("manifest_json = %v, want nil", got.ManifestJSON)
	}

	if got.OverallGrade != nil {
		t.Fatalf("overall_grade = %v, want nil", got.OverallGrade)
	}
}

func assertWipedPermanentIdentityPII(t *testing.T, got *TestRun) {
	t.Helper()

	if got.BobUserID != nil {
		t.Fatalf("bob_user_id = %v, want nil", got.BobUserID)
	}

	if got.ReverseInviteToken != nil {
		t.Fatalf("reverse_invite_token = %v, want nil", got.ReverseInviteToken)
	}

	if got.ReverseInviteImportedAt != nil {
		t.Fatalf("reverse_invite_imported_at = %v, want nil", got.ReverseInviteImportedAt)
	}

	if got.ReverseShareProviderID != nil {
		t.Fatalf("reverse_share_provider_id = %v, want nil", got.ReverseShareProviderID)
	}

	if got.DesignatedShareWith != nil {
		t.Fatalf("designated_share_with = %v, want nil", got.DesignatedShareWith)
	}

	if got.StarterOCMID != nil {
		t.Fatalf("starter_ocm_id = %v, want nil", got.StarterOCMID)
	}

	if got.S1ClaimedAt != nil {
		t.Fatalf("s1_claimed_at = %v, want nil", got.S1ClaimedAt)
	}

	if got.OutgoingInviteID != nil {
		t.Fatalf("outgoing_invite_id = %v, want nil", got.OutgoingInviteID)
	}
}

func assertOutgoingInviteReusableAfterTombstone(
	t *testing.T,
	db *gorm.DB,
	ctx context.Context,
	tombstonedID string,
	now int64,
) {
	t.Helper()

	inviteID := seedOutgoingInviteID(tombstonedID)
	reuse := &TestRun{
		TestRunID:        "run-reuse-outgoing-invite",
		State:            StateCreated,
		TargetOrigin:     "https://reuse.example",
		TargetHost:       "reuse.example",
		DiscoveryURL:     "https://reuse.example/.well-known/ocm",
		ManifestSchema:   "ocm-validator-manifest/v1",
		OutgoingInviteID: &inviteID,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := db.WithContext(ctx).Create(reuse).Error; err != nil {
		t.Fatalf(
			"reuse outgoing_invite_id %q after tombstone: %v (unique index must be free)",
			inviteID,
			err,
		)
	}
}

func seedOutgoingInviteID(runID string) string {
	return "invite-" + runID
}

func assertStatsRawCount(t *testing.T, db *gorm.DB, ctx context.Context, want int64) {
	t.Helper()

	var rawCount int64
	if err := db.WithContext(ctx).Model(&StatsRaw{}).Count(&rawCount).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	if rawCount != want {
		t.Fatalf("stats_raw rows = %d, want %d (expiry must not prune stats)", rawCount, want)
	}
}

func seedExpiredPermanentRun(
	t *testing.T,
	db *gorm.DB,
	ctx context.Context,
	id string,
	finished, expires int64,
) {
	t.Helper()

	manifest := `{"k":"v"}`
	grade := GradePass
	bob := "bob-pii"
	token := "invite-token"
	shareWith := "alice@pii.example"
	provider := "prov-pii"
	starter := "ocm-starter-pii"
	outgoingInvite := seedOutgoingInviteID(id)
	tier := RetentionTier7
	reportID := id

	row := &TestRun{
		TestRunID:               id,
		State:                   StateTerminalPass,
		TargetOrigin:            "https://pii.example",
		TargetHost:              "pii.example",
		StarterOCMID:            &starter,
		OutgoingInviteID:        &outgoingInvite,
		DiscoveryURL:            "https://pii.example/.well-known/ocm",
		JwksURI:                 "https://pii.example/jwks.json",
		ManifestSchema:          "ocm-validator-manifest/v1",
		ManifestJSON:            &manifest,
		OverallGrade:            &grade,
		BobUserID:               &bob,
		S1ClaimedAt:             &finished,
		ReverseInviteToken:      &token,
		ReverseInviteImportedAt: &finished,
		DesignatedShareWith:     &shareWith,
		ReverseShareProviderID:  &provider,
		OptInPermanent:          true,
		OptInActive:             true,
		RetentionTier:           &tier,
		ExpiresAt:               &expires,
		PermanentReportID:       &reportID,
		FinishedAt:              &finished,
		CreatedAt:               finished,
		UpdatedAt:               finished,
	}

	if err := db.WithContext(ctx).Create(row).Error; err != nil {
		t.Fatalf("seed expired permanent %s: %v", id, err)
	}
}

func seedExpiryChildRows(t *testing.T, db *gorm.DB, runID string) {
	t.Helper()

	mustExec(t, db, `INSERT INTO share_correlation
		(test_run_id, role, sender_host, provider_id, local_identity, status, created_at)
		VALUES ('`+runID+`', 'outgoing_to_target', 'pii.example', 'prov-`+runID+`', 'a', 'confirmed', 1)`)
	mustExec(t, db, `INSERT INTO report_exchange
		(test_run_id, seq, captured_at, direction, actor, endpoint_id, method, url, created_at)
		VALUES ('`+runID+`', 1, 1, 'out', 'validator', 'discovery', 'GET', 'https://pii.example/x', 1)`)
	mustExec(t, db, `INSERT INTO evidence_row
		(test_run_id, area, step, reason_code, severity, affects_grade, exchange_id, created_at)
		VALUES ('`+runID+`', 'discovery', 'request', 'timeout', 'important', TRUE, 1, 1)`)
	mustExec(t, db, `INSERT INTO dispatch_reservation
		(test_run_id, provider_id, webdav_id, shared_secret, receiver_host, share_with, probe_file_path, status, created_at)
		VALUES ('`+runID+`', 'prov-`+runID+`', 'wd-`+runID+`', 'secret', 'receiver.example', 'bob', '/probe.bin', 'dispatch_reserved', 1)`)
}
