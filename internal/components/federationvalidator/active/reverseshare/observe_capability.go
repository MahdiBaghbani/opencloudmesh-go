// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseshare

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// Forward capability evidence tuple observed by this leg. The strings are the
// first-wins reason codes the store seam's capability advance keys on; the
// reverse leg records them through the shared evidence seam and never
// terminalizes from them.
const (
	evidenceAreaCapability      = "capability"
	evidenceStepFileOpened      = "file_opened"
	evidenceReasonTokenExchange = "token_exchange"
	evidenceReasonWebDAVGet     = "webdav_get"
	evidenceLegForward          = "forward"
)

// ObserveTokenExchange is the post-exchange hook on the token endpoint: the
// peer completed the authorization-code exchange for one of this server's
// outgoing shares, which is the capability exercise when the share is the
// active run's dispatched share.
func (s *Service) ObserveTokenExchange(ctx context.Context, share *sharesoutgoing.OutgoingShare) error {
	return s.observeCapabilityExercise(ctx, share, evidenceReasonTokenExchange)
}

// ObserveWebDAVGet is the post-authorization hook on the WebDAV GET path: the
// peer opened the shared file through one of this server's outgoing shares,
// which is the capability exercise when the share is the active run's
// dispatched share.
func (s *Service) ObserveWebDAVGet(ctx context.Context, share *sharesoutgoing.OutgoingShare) error {
	return s.observeCapabilityExercise(ctx, share, evidenceReasonWebDAVGet)
}

// observeCapabilityExercise records the forward capability fact for the
// active run whose dispatch reservation owns the exercised share, heals the
// advance across the commit race, then opens the event-driven reverse-share
// wait in the same request. Shares that resolve to no run, or to a run whose
// reservation pins a different provider id, exercise no validator capability
// and are ignored. Every step is idempotent, so a retried exchange or GET
// re-enters safely.
func (s *Service) observeCapabilityExercise(
	ctx context.Context,
	share *sharesoutgoing.OutgoingShare,
	reason string,
) error {
	if share == nil {
		return nil
	}

	runID, err := s.deps.Store.FindOneActive(ctx, validatorcore.LocalIdentityA)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("reverseshare: find active run: %w", err)
	}

	reservation, err := s.deps.Store.GetDispatchReservation(ctx, runID)
	if errors.Is(err, validatorcore.ErrDispatchReservationNotFound) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("reverseshare: load dispatch reservation: %w", err)
	}

	if reservation.ProviderID != share.ProviderID {
		return nil
	}

	if err := s.deps.Store.ApplyEvidenceFact(ctx, validatorcore.ApplyEvidenceFactInput{
		TestRunID:    runID,
		Area:         evidenceAreaCapability,
		Step:         evidenceStepFileOpened,
		ReasonCode:   reason,
		Severity:     validatorcore.GradePass,
		AffectsGrade: true,
		Leg:          evidenceLegForward,
	}); err != nil {
		return fmt.Errorf("reverseshare: apply capability evidence: %w", err)
	}

	// The fact may have landed before the forward-share commit CAS; the
	// presence heal runs the advance with the identical from-set so the
	// exercise is durable before the wait opens.
	if err := s.deps.Store.HealForwardSharePresence(ctx, runID); err != nil {
		return fmt.Errorf("reverseshare: heal capability presence: %w", err)
	}

	return s.OpenReverseShareWait(ctx, runID)
}
