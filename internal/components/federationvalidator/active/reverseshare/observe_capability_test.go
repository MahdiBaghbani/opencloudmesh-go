// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseshare_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// seedReservation stores the run's dispatch reservation row the way the
// forward-share guard leaves it after the designated dispatch. The write is
// table-scoped because the reservation's UpdatedAt is a nullable unix column
// GORM's name-based auto timestamping cannot fill.
func (e *testEnv) seedReservation(t *testing.T, runID, providerID string) {
	t.Helper()

	table := validatorcore.DispatchReservation{}.TableName()

	if err := e.store.DB().WithContext(t.Context()).Table(table).Create(map[string]any{
		"test_run_id":     runID,
		"provider_id":     providerID,
		"webdav_id":       uuid.NewString(),
		"shared_secret":   uuid.NewString(),
		"receiver_host":   testTargetHost,
		"share_with":      "user@" + testTargetHost,
		"probe_file_path": "/probe.txt",
		"status":          validatorcore.DispatchStatusCASCommitted,
		"created_at":      time.Now().Unix(),
	}).Error; err != nil {
		t.Fatalf("seed reservation %s: %v", runID, err)
	}
}

func (e *testEnv) countEvidence(t *testing.T, runID string) int64 {
	t.Helper()

	var count int64
	if err := e.store.DB().WithContext(t.Context()).
		Model(&validatorcore.EvidenceRow{}).
		Where("test_run_id = ?", runID).
		Count(&count).Error; err != nil {
		t.Fatalf("count evidence: %v", err)
	}

	return count
}

func exerciseShare(providerID string) *sharesoutgoing.OutgoingShare {
	return &sharesoutgoing.OutgoingShare{
		ShareID:      uuid.NewString(),
		ProviderID:   providerID,
		ReceiverHost: testTargetHost,
	}
}

func TestObserveTokenExchange_AdvancesAndOpensWait(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.seedRun(t, "run-observe-token", validatorcore.StateForwardShareSent)
	env.seedReservation(t, "run-observe-token", "provider-token")

	if err := env.svc.ObserveTokenExchange(t.Context(), exerciseShare("provider-token")); err != nil {
		t.Fatalf("ObserveTokenExchange: %v", err)
	}

	run := env.requireRun(t, "run-observe-token")

	if run.State != validatorcore.StateReverseAwaitingShare {
		t.Fatalf("state = %q, want %q (exercise advances, then the wait opens)",
			run.State, validatorcore.StateReverseAwaitingShare)
	}

	if count := env.countEvidence(t, "run-observe-token"); count != 2 {
		t.Fatalf("evidence count = %d, want 2 (token area plus capability)", count)
	}
}

func TestObserveWebDAVGet_AdvancesAndOpensWait(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.seedRun(t, "run-observe-get", validatorcore.StateForwardShareSent)
	env.seedReservation(t, "run-observe-get", "provider-get")

	if err := env.svc.ObserveWebDAVGet(t.Context(), exerciseShare("provider-get")); err != nil {
		t.Fatalf("ObserveWebDAVGet: %v", err)
	}

	run := env.requireRun(t, "run-observe-get")

	if run.State != validatorcore.StateReverseAwaitingShare {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateReverseAwaitingShare)
	}

	if count := env.countEvidence(t, "run-observe-get"); count != 2 {
		t.Fatalf("evidence count = %d, want 2 (webdav transcript plus capability)", count)
	}
}

func TestObserveCapabilityExercise_NoActiveRunNoOps(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)

	if err := env.svc.ObserveTokenExchange(t.Context(), exerciseShare("provider-none")); err != nil {
		t.Fatalf("ObserveTokenExchange: %v", err)
	}
}

func TestObserveCapabilityExercise_NoReservationNoOps(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.seedRun(t, "run-observe-no-res", validatorcore.StateForwardShareSent)

	if err := env.svc.ObserveTokenExchange(t.Context(), exerciseShare("provider-no-res")); err != nil {
		t.Fatalf("ObserveTokenExchange: %v", err)
	}

	run := env.requireRun(t, "run-observe-no-res")

	if run.State != validatorcore.StateForwardShareSent {
		t.Fatalf("state = %q, want unchanged %q", run.State, validatorcore.StateForwardShareSent)
	}
}

func TestObserveCapabilityExercise_ProviderMismatchNoOps(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.seedRun(t, "run-observe-mismatch", validatorcore.StateForwardShareSent)
	env.seedReservation(t, "run-observe-mismatch", "provider-owned")

	if err := env.svc.ObserveTokenExchange(t.Context(), exerciseShare("provider-foreign")); err != nil {
		t.Fatalf("ObserveTokenExchange: %v", err)
	}

	run := env.requireRun(t, "run-observe-mismatch")

	if run.State != validatorcore.StateForwardShareSent {
		t.Fatalf("state = %q, want unchanged %q", run.State, validatorcore.StateForwardShareSent)
	}

	if count := env.countEvidence(t, "run-observe-mismatch"); count != 0 {
		t.Fatalf("evidence count = %d, want 0 (foreign share records no fact)", count)
	}
}

func TestObserveCapabilityExercise_NilShareNoOps(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.seedRun(t, "run-observe-nil", validatorcore.StateForwardShareSent)
	env.seedReservation(t, "run-observe-nil", "provider-nil")

	if err := env.svc.ObserveTokenExchange(t.Context(), nil); err != nil {
		t.Fatalf("ObserveTokenExchange: %v", err)
	}

	run := env.requireRun(t, "run-observe-nil")

	if run.State != validatorcore.StateForwardShareSent {
		t.Fatalf("state = %q, want unchanged %q", run.State, validatorcore.StateForwardShareSent)
	}
}

func TestObserveCapabilityExercise_EarlyArrivedSharePasses(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	bobID := env.seedRun(t, "run-observe-early", validatorcore.StateForwardShareSent)
	env.seedReservation(t, "run-observe-early", "provider-early")
	env.addShare(t, bobID, "provider-reverse-early", testTargetHost)

	if err := env.svc.ObserveTokenExchange(t.Context(), exerciseShare("provider-early")); err != nil {
		t.Fatalf("ObserveTokenExchange: %v", err)
	}

	run := env.requireRun(t, "run-observe-early")

	if run.State != validatorcore.StateTerminalPass {
		t.Fatalf("state = %q, want %q (exercise opens the wait, early share passes)",
			run.State, validatorcore.StateTerminalPass)
	}
}

func TestObserveCapabilityExercise_CommitRaceHealsOnNextExercise(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()

	// The peer's exchange lands before the forward-share commit CAS: the fact
	// is recorded but the advance cannot fire from reverse_invite_accepted.
	env.seedRun(t, "run-observe-race", validatorcore.StateReverseInviteAccepted)
	env.seedReservation(t, "run-observe-race", "provider-race")

	if err := env.svc.ObserveTokenExchange(ctx, exerciseShare("provider-race")); err != nil {
		t.Fatalf("ObserveTokenExchange: %v", err)
	}

	run := env.requireRun(t, "run-observe-race")

	if run.State != validatorcore.StateReverseInviteAccepted {
		t.Fatalf("state = %q, want unchanged %q before the commit",
			run.State, validatorcore.StateReverseInviteAccepted)
	}

	// The commit CAS lands, moving the run to forward_share_sent.
	res := env.store.DB().WithContext(ctx).Model(&validatorcore.TestRun{}).
		Where("test_run_id = ?", "run-observe-race").
		Updates(map[string]any{"state": validatorcore.StateForwardShareSent, "updated_at": time.Now().Unix()})
	if res.Error != nil {
		t.Fatalf("simulate commit CAS: %v", res.Error)
	}

	// The peer's next exercise presence-heals the recorded fact and opens the
	// wait in the same request.
	if err := env.svc.ObserveWebDAVGet(ctx, exerciseShare("provider-race")); err != nil {
		t.Fatalf("ObserveWebDAVGet: %v", err)
	}

	run = env.requireRun(t, "run-observe-race")

	if run.State != validatorcore.StateReverseAwaitingShare {
		t.Fatalf("state = %q, want %q after the presence heal",
			run.State, validatorcore.StateReverseAwaitingShare)
	}

	if count := env.countEvidence(t, "run-observe-race"); count != 4 {
		t.Fatalf("evidence count = %d, want 4 (token, webdav transcript, two capability reasons)", count)
	}
}

func TestObserveCapabilityExercise_IdempotentRetry(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()
	env.seedRun(t, "run-observe-retry", validatorcore.StateForwardShareSent)
	env.seedReservation(t, "run-observe-retry", "provider-retry")

	if err := env.svc.ObserveTokenExchange(ctx, exerciseShare("provider-retry")); err != nil {
		t.Fatalf("first ObserveTokenExchange: %v", err)
	}

	if err := env.svc.ObserveTokenExchange(ctx, exerciseShare("provider-retry")); err != nil {
		t.Fatalf("retry ObserveTokenExchange: %v", err)
	}

	run := env.requireRun(t, "run-observe-retry")

	if run.State != validatorcore.StateReverseAwaitingShare {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateReverseAwaitingShare)
	}

	if count := env.countEvidence(t, "run-observe-retry"); count != 2 {
		t.Fatalf("evidence count = %d, want 2 (first-wins token and capability)", count)
	}
}
