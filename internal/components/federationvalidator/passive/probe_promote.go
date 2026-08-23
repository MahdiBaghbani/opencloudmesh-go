// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func (p *ProbeRunner) promoteOrWait(ctx context.Context, testRunID string) error {
	if p == nil || p.store == nil {
		return nil
	}

	casWon, err := p.store.ExtendToActiveCAS(ctx, testRunID)
	if err == nil {
		if casWon {
			p.store.RememberPendingPromote(testRunID)
			p.store.FlushPromoteFollowUp(ctx)
		}

		return nil
	}

	if validatorcore.IsActiveSlotBusy(err) {
		if stampErr := p.store.StampPassiveReadyAt(ctx, testRunID); stampErr != nil {
			return fmt.Errorf("passive: stamp ready waiter: %w", stampErr)
		}

		return nil
	}

	return fmt.Errorf("passive: promote to active: %w", err)
}

func (h *Handler) deliverPromoteFollowUp(ctx context.Context, testRunID string) bool {
	if h == nil || h.probe == nil {
		return false
	}

	h.receiverMu.Lock()
	wired := h.parties != nil
	h.receiverMu.Unlock()

	if !wired {
		return false
	}

	return promoteFollowUp{
		materialize: h.materializeReverseReceiver,
		kick:        h.probe.kick,
		log:         h.log,
	}.run(ctx, testRunID)
}

// promoteFollowUp is the shared post-ExtendToActive seam: materialize
// Bob, then Kick the wake-only active runner. Probe promotion and
// startup promotion both invoke it so a startup-promoted waiter cannot
// skip Bob or Kick. A nil materialize, or a materialize error, defers
// the whole follow-up (including Kick) until a later flush succeeds.
type promoteFollowUp struct {
	materialize func(context.Context, string) error
	kick        ActiveKicker
	log         *slog.Logger
}

func (f promoteFollowUp) run(ctx context.Context, testRunID string) bool {
	if f.materialize == nil {
		return false
	}

	if followErr := f.materialize(ctx, testRunID); followErr != nil {
		if f.log != nil {
			f.log.Warn("active promote follow-up failed", "test_run_id", testRunID, "error", followErr)
		}

		return false
	}

	if f.kick != nil {
		f.kick.Kick()
	}

	return true
}

func (h *Handler) bindPromoteFollowUp() {
	if h == nil || h.store == nil || h.probe == nil {
		return
	}

	h.store.SetPromoteFollowUp(h.deliverPromoteFollowUp)
	h.flushPromoteFollowUp()
}

func (h *Handler) flushPromoteFollowUp() {
	if h == nil || h.store == nil {
		return
	}

	h.store.FlushPromoteFollowUp(context.Background())
}
