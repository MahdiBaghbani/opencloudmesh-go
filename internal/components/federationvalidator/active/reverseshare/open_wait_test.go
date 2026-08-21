// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseshare_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// arrivingInbox wraps the incoming-share repo so the first inbox listing
// stores a new share before returning empty, simulating a share that lands
// between the pre-CAS scan and the post-CAS scan of OpenReverseShareWait.
type arrivingInbox struct {
	inner    sharesincoming.IncomingShareRepo
	share    *sharesincoming.IncomingShare
	injected atomic.Bool
}

func (r *arrivingInbox) Create(ctx context.Context, share *sharesincoming.IncomingShare) error {
	if err := r.inner.Create(ctx, share); err != nil {
		return fmt.Errorf("arriving inbox create: %w", err)
	}

	return nil
}

func (r *arrivingInbox) GetByIDForRecipientUserID(
	ctx context.Context,
	shareID, recipientUserID string,
) (*sharesincoming.IncomingShare, error) {
	share, err := r.inner.GetByIDForRecipientUserID(ctx, shareID, recipientUserID)
	if err != nil {
		return nil, fmt.Errorf("arriving inbox get: %w", err)
	}

	return share, nil
}

func (r *arrivingInbox) GetByProviderID(
	ctx context.Context,
	senderHost, providerID string,
) (*sharesincoming.IncomingShare, error) {
	share, err := r.inner.GetByProviderID(ctx, senderHost, providerID)
	if err != nil {
		return nil, fmt.Errorf("arriving inbox get by provider: %w", err)
	}

	return share, nil
}

func (r *arrivingInbox) ListByRecipientUserID(
	ctx context.Context,
	recipientUserID string,
) ([]*sharesincoming.IncomingShare, error) {
	if r.share != nil && r.injected.CompareAndSwap(false, true) {
		if err := r.inner.Create(ctx, r.share); err != nil {
			return nil, fmt.Errorf("arriving inbox inject: %w", err)
		}

		return []*sharesincoming.IncomingShare{}, nil
	}

	list, err := r.inner.ListByRecipientUserID(ctx, recipientUserID)
	if err != nil {
		return nil, fmt.Errorf("arriving inbox list: %w", err)
	}

	return list, nil
}

func (r *arrivingInbox) UpdateStatusForRecipientUserID(
	ctx context.Context,
	shareID, recipientUserID string,
	status shares.ShareStatus,
) error {
	if err := r.inner.UpdateStatusForRecipientUserID(ctx, shareID, recipientUserID, status); err != nil {
		return fmt.Errorf("arriving inbox update status: %w", err)
	}

	return nil
}

func (r *arrivingInbox) DeleteForRecipientUserID(ctx context.Context, shareID, recipientUserID string) error {
	if err := r.inner.DeleteForRecipientUserID(ctx, shareID, recipientUserID); err != nil {
		return fmt.Errorf("arriving inbox delete: %w", err)
	}

	return nil
}

func TestOpenReverseShareWait_OpensWaitFromCapabilityExercise(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.seedRun(t, "run-open-wait", validatorcore.StateCapabilityExercise)

	if err := env.svc.OpenReverseShareWait(t.Context(), "run-open-wait"); err != nil {
		t.Fatalf("OpenReverseShareWait: %v", err)
	}

	run := env.requireRun(t, "run-open-wait")

	if run.State != validatorcore.StateReverseAwaitingShare {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateReverseAwaitingShare)
	}

	if !run.IsActive {
		t.Fatal("is_active = 0, want the wait to keep the active lock")
	}
}

func TestOpenReverseShareWait_NoOpsOutsideCapabilityExercise(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.seedRun(t, "run-open-noop", validatorcore.StateForwardShareSent)

	if err := env.svc.OpenReverseShareWait(t.Context(), "run-open-noop"); err != nil {
		t.Fatalf("OpenReverseShareWait: %v", err)
	}

	run := env.requireRun(t, "run-open-noop")

	if run.State != validatorcore.StateForwardShareSent {
		t.Fatalf("state = %q, want unchanged %q", run.State, validatorcore.StateForwardShareSent)
	}
}

func TestOpenReverseShareWait_EarlyArrivedSharePassesImmediately(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	bobID := env.seedRun(t, "run-open-early", validatorcore.StateCapabilityExercise)
	env.addShare(t, bobID, "provider-before-wait", testTargetHost)

	if err := env.svc.OpenReverseShareWait(t.Context(), "run-open-early"); err != nil {
		t.Fatalf("OpenReverseShareWait: %v", err)
	}

	run := env.requireRun(t, "run-open-early")

	if run.State != validatorcore.StateTerminalPass {
		t.Fatalf("state = %q, want %q (early share passes instead of opening the wait)",
			run.State, validatorcore.StateTerminalPass)
	}

	if run.ReverseShareProviderID == nil || *run.ReverseShareProviderID != "provider-before-wait" {
		t.Fatalf("reverse_share_provider_id = %v, want %q",
			run.ReverseShareProviderID, "provider-before-wait")
	}

	if count := env.countStatsRaw(t); count != 1 {
		t.Fatalf("stats_raw count = %d, want 1", count)
	}
}

func TestOpenReverseShareWait_IgnoresSharesFromOtherSenders(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	bobID := env.seedRun(t, "run-open-other-sender", validatorcore.StateCapabilityExercise)
	env.addShare(t, bobID, "provider-unrelated", "unrelated.example")

	if err := env.svc.OpenReverseShareWait(t.Context(), "run-open-other-sender"); err != nil {
		t.Fatalf("OpenReverseShareWait: %v", err)
	}

	run := env.requireRun(t, "run-open-other-sender")

	if run.State != validatorcore.StateReverseAwaitingShare {
		t.Fatalf("state = %q, want %q (unrelated share must not pass the run)",
			run.State, validatorcore.StateReverseAwaitingShare)
	}
}

func TestOpenReverseShareWait_PostCASScanClosesArrivalWindow(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	bobID := env.seedRun(t, "run-open-toctou", validatorcore.StateCapabilityExercise)

	arriving := &sharesincoming.IncomingShare{
		ShareID:         uuid.NewString(),
		ProviderID:      "provider-mid-open",
		SenderHost:      testTargetHost,
		RecipientUserID: bobID,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	svc, err := newServiceWithShares(t, env.store, &arrivingInbox{inner: env.shares, share: arriving})
	if err != nil {
		t.Fatalf("reverseshare.New: %v", err)
	}

	if err := svc.OpenReverseShareWait(t.Context(), "run-open-toctou"); err != nil {
		t.Fatalf("OpenReverseShareWait: %v", err)
	}

	run := env.requireRun(t, "run-open-toctou")

	if run.State != validatorcore.StateTerminalPass {
		t.Fatalf("state = %q, want %q (share arriving mid-open must still pass the run)",
			run.State, validatorcore.StateTerminalPass)
	}
}

func TestOpenReverseShareWait_DoesNotHealTerminalStatsGap(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()

	// An opted-in terminal row whose stats write never landed, next to the
	// active run the wait opens for. Global recovery runs on the periodic
	// store ticker, not on this hot path.
	finished := time.Now().Unix()

	if err := env.store.DB().WithContext(ctx).Create(&validatorcore.TestRun{
		TestRunID:    "run-open-heal-gap",
		IsActive:     false,
		State:        validatorcore.StateTerminalPass,
		TargetOrigin: testTargetOrigin,
		TargetHost:   testTargetHost,
		FinishedAt:   &finished,
		OptInStats:   true,
		CreatedAt:    finished,
		UpdatedAt:    finished,
	}).Error; err != nil {
		t.Fatalf("seed stats gap: %v", err)
	}

	env.seedRun(t, "run-open-heal", validatorcore.StateCapabilityExercise)

	if err := env.svc.OpenReverseShareWait(ctx, "run-open-heal"); err != nil {
		t.Fatalf("OpenReverseShareWait: %v", err)
	}

	gap := env.requireRun(t, "run-open-heal-gap")

	if gap.StatsWrittenAt != nil {
		t.Fatalf("stats_written_at = %v, want nil: the wait-open path never runs the global heal", gap.StatsWrittenAt)
	}

	if count := env.countStatsRaw(t); count != 0 {
		t.Fatalf("stats_raw count = %d, want 0 (no heal on wait-open)", count)
	}
}
