// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package forwardshare_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestCourierMatrix_LegCheckpoints(t *testing.T) {
	t.Parallel()

	t.Run("reverse_invitation", testCourierMatrixReverseInvitation)
	t.Run("forward_share", testCourierMatrixForwardShare)
}

func testCourierMatrixReverseInvitation(t *testing.T) {
	t.Parallel()

	env := newCourierMatrixEnv(t)
	runID := env.startActiveSession(t)
	env.acceptForwardInvite(t, runID)
	env.pasteReverseInvite(t, runID)

	env.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	if got := env.countEvidence(t, runID); got != 1 {
		t.Fatalf("evidence rows = %d, want 1", got)
	}

	if got := len(env.listShares(t)); got != 0 {
		t.Fatalf("outgoing shares = %d, want 0", got)
	}

	requireNoTerminalFootprint(t, env, runID)

	run := env.requireRun(t, runID)

	score, _, err := env.store.LoadSpecificationRating(t.Context(), run)
	if err != nil {
		t.Fatalf("LoadSpecificationRating: %v", err)
	}

	if score.Terminal {
		t.Fatal("rater terminal = true, want false")
	}

	if score.Grade != nil {
		t.Fatalf("rater grade = %q, want nil", *score.Grade)
	}

	sharing := requireAreaScore(t, score, validatorcore.SpecificationAreaSharing)

	if sharing.Grade == nil || *sharing.Grade != validatorcore.GradePass {
		t.Fatalf("sharing area grade = %v, want %q", sharing.Grade, validatorcore.GradePass)
	}
}

func testCourierMatrixForwardShare(t *testing.T) {
	t.Parallel()

	env := newCourierMatrixEnv(t)
	runID := env.startActiveSession(t)
	env.acceptForwardInvite(t, runID)
	env.pasteReverseInvite(t, runID)
	env.dispatchForwardShare(t, runID)

	env.requireState(t, runID, validatorcore.StateForwardShareSent)

	reservation := env.requireReservation(t, runID)

	if reservation.Status != validatorcore.DispatchStatusCASCommitted {
		t.Fatalf("reservation status = %q, want %q", reservation.Status, validatorcore.DispatchStatusCASCommitted)
	}

	if got := len(env.evidenceRows(t, runID, "capability", "file_opened", "token_exchange")); got != 0 {
		t.Fatalf("capability evidence rows = %d, want 0", got)
	}

	run := env.requireRun(t, runID)

	inbox, err := env.repos.IncomingShares.ListByRecipientUserID(t.Context(), *run.BobUserID)
	if err != nil {
		t.Fatalf("list incoming shares: %v", err)
	}

	if len(inbox) != 0 {
		t.Fatalf("incoming shares = %d, want 0", len(inbox))
	}

	if run.FinishedAt != nil || run.TerminalReason != nil || run.OverallGrade != nil {
		t.Fatalf("terminal fields = (%v, %v, %v), want all nil",
			run.FinishedAt, run.TerminalReason, run.OverallGrade)
	}

	if got := env.countStatsRaw(t); got != 0 {
		t.Fatalf("stats_raw rows = %d, want 0", got)
	}
}

func TestCourierMatrix_TerminalOutcomes(t *testing.T) {
	t.Parallel()

	t.Run("pass", testCourierMatrixTerminalPass)
	t.Run("hard_fail", testCourierMatrixHardFail)
	t.Run("interrupted_then_late_pass", testCourierMatrixInterruptedLatePass)
}

func testCourierMatrixTerminalPass(t *testing.T) {
	t.Parallel()

	env := newCourierMatrixEnv(t)
	runID := env.startActiveSession(t)
	env.acceptForwardInvite(t, runID)
	env.pasteReverseInvite(t, runID)
	env.dispatchForwardShare(t, runID)
	env.exerciseForwardCapability(t, runID)

	bobID := *env.requireRun(t, runID).BobUserID

	providerID := env.deliverReverseShare(t, runID, "reverse_share_observed")

	run := env.requireRun(t, runID)

	if run.IsActive {
		t.Fatal("is_active = true, want false")
	}

	if run.BobUserID == nil || *run.BobUserID != bobID {
		t.Fatalf("bob_user_id = %v, want preserved %q", run.BobUserID, bobID)
	}

	if run.ReverseShareProviderID == nil || *run.ReverseShareProviderID != providerID {
		t.Fatalf("reverse_share_provider_id = %v, want %q", run.ReverseShareProviderID, providerID)
	}

	requirePassEvidenceTuple(t, env, runID)

	score := requireRaterOutcome(t, env, run, validatorcore.StateTerminalPass, validatorcore.GradePass)

	sharing := requireAreaScore(t, score, validatorcore.SpecificationAreaSharing)

	if sharing.Grade == nil || *sharing.Grade != validatorcore.GradePass {
		t.Fatalf("sharing area grade = %v, want %q", sharing.Grade, validatorcore.GradePass)
	}

	capability := requireAreaScore(t, score, validatorcore.SpecificationAreaCapability)

	if capability.Grade == nil || *capability.Grade != validatorcore.GradePass {
		t.Fatalf("capability area grade = %v, want %q", capability.Grade, validatorcore.GradePass)
	}

	if score.AssessedAreas != 2 {
		t.Fatalf("assessed areas = %d, want 2", score.AssessedAreas)
	}

	if score.TotalAreas != 8 {
		t.Fatalf("total areas = %d, want 8", score.TotalAreas)
	}
}

func testCourierMatrixHardFail(t *testing.T) {
	t.Parallel()

	env := newCourierMatrixEnv(t)
	runID := env.startActiveSession(t)
	env.acceptForwardInvite(t, runID)
	env.pasteReverseInvite(t, runID)

	applySharingFailure(t, env, runID)

	if err := env.store.ReleaseActiveHardFail(t.Context(), runID, validatorcore.ReasonActiveHardFailCorrelation); err != nil {
		t.Fatalf("release hard fail: %v", err)
	}

	run := env.requireRun(t, runID)

	if run.State != validatorcore.StateTerminalFail {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateTerminalFail)
	}

	if run.TerminalReason == nil || *run.TerminalReason != validatorcore.ReasonActiveHardFailCorrelation {
		t.Fatalf("terminal_reason = %v, want %q", run.TerminalReason, validatorcore.ReasonActiveHardFailCorrelation)
	}

	if run.IsActive {
		t.Fatal("is_active = true, want false")
	}

	if got := env.countStatsRaw(t); got != 1 {
		t.Fatalf("stats_raw rows = %d, want 1", got)
	}

	raw := env.statsRawForRun(t, runID)

	if raw.GradeSharing == nil || *raw.GradeSharing != validatorcore.GradeFail {
		t.Fatalf("raw sharing grade = %v, want %q", raw.GradeSharing, validatorcore.GradeFail)
	}

	requireRaterOutcome(t, env, run, validatorcore.StateTerminalFail, validatorcore.GradeFail)

	if err := env.store.ReleaseActiveHardFail(t.Context(), runID, validatorcore.ReasonActiveHardFailCorrelation); !errors.Is(err, validatorcore.ErrStateTransitionMiss) {
		t.Fatalf("retry hard fail err = %v, want ErrStateTransitionMiss", err)
	}

	retryTerminalStats(t, env, runID)

	if got := env.countStatsRaw(t); got != 1 {
		t.Fatalf("stats_raw rows after retry = %d, want 1", got)
	}
}

func testCourierMatrixInterruptedLatePass(t *testing.T) {
	t.Parallel()

	env := newCourierMatrixEnv(t)
	runID := env.startActiveSession(t)
	env.acceptForwardInvite(t, runID)
	env.pasteReverseInvite(t, runID)
	env.dispatchForwardShare(t, runID)
	env.exerciseForwardCapability(t, runID)

	env.requireState(t, runID, validatorcore.StateReverseAwaitingShare)

	releaseInterruptedOnTimeout(t, env, runID)

	interrupted := env.requireRun(t, runID)

	if interrupted.FinishedAt == nil {
		t.Fatal("finished_at is nil after interruption")
	}

	finishedAt := *interrupted.FinishedAt
	rawBefore := env.statsRawForRun(t, runID)

	k, err := env.hasher.HashStatsK(runID)
	if err != nil {
		t.Fatalf("HashStatsK: %v", err)
	}

	requireRaterOutcome(t, env, interrupted, validatorcore.StateInterrupted, "")

	providerID := env.deliverReverseShare(t, runID, validatorcore.ReasonLateReverseShare)

	run := env.requireRun(t, runID)

	if run.FinishedAt == nil || *run.FinishedAt != finishedAt {
		t.Fatalf("finished_at = %v, want preserved %d", run.FinishedAt, finishedAt)
	}

	rawAfter := env.statsRawForRun(t, runID)

	if rawAfter.ID != rawBefore.ID {
		t.Fatalf("raw row id = %d, want preserved %d", rawAfter.ID, rawBefore.ID)
	}

	if rawAfter.K != k {
		t.Fatalf("raw row k = %q, want %q", rawAfter.K, k)
	}

	if got := env.countStatsRaw(t); got != 1 {
		t.Fatalf("stats_raw rows = %d, want 1", got)
	}

	observeDuplicateShare(t, env, run, providerID)

	if got := env.countStatsRaw(t); got != 1 {
		t.Fatalf("stats_raw rows after duplicate = %d, want 1", got)
	}

	run = env.requireRun(t, runID)

	if run.ReverseShareProviderID == nil || *run.ReverseShareProviderID != providerID {
		t.Fatalf("reverse_share_provider_id = %v, want %q", run.ReverseShareProviderID, providerID)
	}

	requireRaterOutcome(t, env, run, validatorcore.StateTerminalPass, validatorcore.GradePass)
}

func TestCourierMatrix_StatsParity(t *testing.T) {
	t.Parallel()

	env := newCourierMatrixEnv(t)

	runs, providers := runStatsParitySessions(t, env)

	for _, id := range runs {
		retryTerminalStats(t, env, id)
		retryTerminalStats(t, env, id)
	}

	ks := requireStatsKeysWritten(t, env, runs)

	hostHash := env.statsRawForRun(t, runs[0]).HostHash
	rawRows := env.statsRawForHost(t, hostHash)

	if len(rawRows) != 3 {
		t.Fatalf("stats_raw rows for host = %d, want 3", len(rawRows))
	}

	for k := range ks {
		if !statsRawContainsK(rawRows, k) {
			t.Fatalf("stats key %q missing from stats_raw", k)
		}
	}

	// The healthy expectation is folded from the seeded runs' raw rows.
	wantHealthy := 0

	for _, id := range runs {
		if validatorcore.DeriveHealthy(env.statsRawForRun(t, id)) {
			wantHealthy++
		}
	}

	aggregate := requireHostAggregate(t, env, hostHash)
	requireAggregateMatchesRaw(t, aggregate, rawRows, wantHealthy)

	assertPublicStatistics(t, env)
	assertRaterRawParity(t, env, runs)

	// Duplicate share callbacks and further stats retries change neither the
	// raw count and aggregate totals nor the public and rater views.
	for _, id := range runs {
		if providerID, ok := providers[id]; ok {
			observeDuplicateShare(t, env, env.requireRun(t, id), providerID)
		}

		retryTerminalStats(t, env, id)
	}

	if got := len(env.statsRawForHost(t, hostHash)); got != 3 {
		t.Fatalf("stats_raw rows for host after duplicates = %d, want 3", got)
	}

	after := requireHostAggregate(t, env, hostHash)

	if after.TotalSessions != 3 || after.HealthySessions != int64(wantHealthy) {
		t.Fatalf("aggregate after duplicates = (%d, %d), want (3, %d)",
			after.TotalSessions, after.HealthySessions, wantHealthy)
	}

	assertPublicStatistics(t, env)
	assertRaterRawParity(t, env, runs)
}

func TestCourierMatrix_EphemeralIdentitiesAndRedaction(t *testing.T) {
	t.Parallel()

	env := newCourierMatrixEnv(t)

	// The first session runs to terminal pass before the second extends.
	run1 := env.startActiveSession(t)
	outToken1 := env.acceptForwardInvite(t, run1)
	token1 := env.pasteReverseInvite(t, run1)
	env.dispatchForwardShare(t, run1)
	env.exerciseForwardCapability(t, run1)
	providerID1 := env.deliverReverseShare(t, run1, "reverse_share_observed")

	// The second session repeats the identity-bound steps inside the session.
	run2 := env.startActiveSession(t)
	outToken2 := env.acceptForwardInvite(t, run2)
	token2 := env.pasteReverseInvite(t, run2)

	assertInSessionIdentityReuse(t, env, run2, outToken2, token2)

	env.dispatchForwardShare(t, run2)
	env.exerciseForwardCapability(t, run2)
	providerID2 := env.deliverReverseShare(t, run2, "reverse_share_observed")

	sensitive := collectSensitiveMarkers(t, env,
		run1, run2, outToken1, outToken2, token1, token2, providerID1, providerID2)
	blobs := collectPublicBlobs(t, env, run1, run2)

	for _, blob := range blobs {
		for _, marker := range sensitive {
			if marker != "" && strings.Contains(blob, marker) {
				t.Fatalf("serialized output contains sensitive marker %q", marker)
			}
		}
	}
}
