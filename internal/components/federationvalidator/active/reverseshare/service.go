// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package reverseshare implements the validator's active reverse-share leg:
// the event-driven wait opened after the capability exercise, the inbound
// share observer that passes the run on a timely or late reverse share, and
// the durable terminal-stats retry behind both.
package reverseshare

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// Evidence tuple recorded when the peer's reverse share reaches Bob. The
// sharing area feeds the terminal statistics sharing grade; the reverse leg
// keeps the fact out of the forward capability advance.
const (
	evidenceAreaSharing         = "sharing"
	evidenceStepReverseShare    = "reverse_share"
	evidenceReasonShareReceived = "reverse_share_received"
	evidenceLegReverse          = "reverse"
	evidenceSeverityInfo        = "info"
)

// Deps carries the collaborators the reverse-share leg needs. LocalIdentity
// supplies the local scheme for the scheme-aware sender-host normalization
// the observer and the inbox scan share with inbound share handling.
type Deps struct {
	Store          *validatorcore.Core
	IncomingShares sharesincoming.IncomingShareRepo
	LocalIdentity  localidentity.Identity
	Logger         *slog.Logger
}

// Service runs the validator reverse-share leg.
type Service struct {
	deps Deps
	log  *slog.Logger
}

// New validates deps and returns the service.
func New(deps Deps) (*Service, error) {
	switch {
	case deps.Store == nil:
		return nil, errors.New("reverseshare: Store is required")
	case deps.IncomingShares == nil:
		return nil, errors.New("reverseshare: IncomingShares is required")
	case deps.LocalIdentity.Scheme == "":
		return nil, errors.New("reverseshare: LocalIdentity.Scheme is required")
	}

	return &Service{deps: deps, log: logutil.NoopIfNil(deps.Logger)}, nil
}

// reverseSharePassUpdate is the terminal update for a run the peer's reverse
// share passed: terminal_pass with the reverse_share_observed reason and a
// pass grade.
func reverseSharePassUpdate() validatorcore.ActiveTerminalUpdate {
	grade := validatorcore.GradePass

	return validatorcore.ActiveTerminalUpdate{
		State:          validatorcore.StateTerminalPass,
		TerminalReason: "reverse_share_observed",
		OverallGrade:   &grade,
	}
}

// recordShareReceived persists the reverse-share evidence fact so terminal
// statistics carry the sharing grade. Best-effort: the fact is first-wins and
// the run row is already loaded by the caller, so a failure only degrades the
// audit trail and never blocks the state transition.
func (s *Service) recordShareReceived(ctx context.Context, testRunID string) {
	err := s.deps.Store.ApplyEvidenceFact(ctx, validatorcore.ApplyEvidenceFactInput{
		TestRunID:    testRunID,
		Area:         evidenceAreaSharing,
		Step:         evidenceStepReverseShare,
		ReasonCode:   evidenceReasonShareReceived,
		Severity:     evidenceSeverityInfo,
		AffectsGrade: true,
		Leg:          evidenceLegReverse,
	})
	if err != nil {
		s.log.Warn("reverse-share evidence not recorded",
			"test_run_id", testRunID,
			"error", err)
	}
}

// driveReverseShareSuccess passes the run for the arrived reverse share. The
// timely path is one expected-state-set CAS from capability_exercise or
// reverse_awaiting_share into terminal_pass; statistics are re-driven with
// their error returned so the caller can withhold success until they land.
// A CAS miss reloads into the late flip in the same request, which also
// covers rows already interrupted by the reverse-share timeout and duplicate
// deliveries of a share that already passed the run. The provider id stamp
// lands only after the run is terminal_pass.
func (s *Service) driveReverseShareSuccess(ctx context.Context, testRunID, providerID string) error {
	run, err := s.deps.Store.GetTestRun(ctx, testRunID)
	if errors.Is(err, validatorcore.ErrSessionNotFound) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("reverseshare: load run: %w", err)
	}

	s.recordShareReceived(ctx, testRunID)

	if run.IsActive && (run.State == validatorcore.StateCapabilityExercise ||
		run.State == validatorcore.StateReverseAwaitingShare) {
		releaseErr := s.deps.Store.ReleaseActiveTerminalFrom(
			ctx,
			testRunID,
			validatorcore.ActivePassExpectedStates(),
			reverseSharePassUpdate(),
		)

		switch {
		case releaseErr == nil:
			if statsErr := s.deps.Store.RetryTerminalStats(ctx, testRunID); statsErr != nil {
				return fmt.Errorf("reverseshare: terminal stats: %w", statsErr)
			}

			return s.stampProviderID(ctx, testRunID, providerID)
		case errors.Is(releaseErr, validatorcore.ErrStateTransitionMiss):
			// The row raced past the pass pre-image between the load and the
			// CAS; the late flip below reloads it in the same request.
		default:
			return fmt.Errorf("reverseshare: release active run: %w", releaseErr)
		}
	}

	passed, err := s.deps.Store.FlipLateReverseShareToPass(ctx, testRunID)
	if err != nil {
		return fmt.Errorf("reverseshare: late flip: %w", err)
	}

	if !passed {
		return nil
	}

	return s.stampProviderID(ctx, testRunID, providerID)
}

func (s *Service) stampProviderID(ctx context.Context, testRunID, providerID string) error {
	if err := s.deps.Store.StampReverseShareProviderID(ctx, testRunID, providerID); err != nil {
		return fmt.Errorf("reverseshare: stamp provider id: %w", err)
	}

	return nil
}
