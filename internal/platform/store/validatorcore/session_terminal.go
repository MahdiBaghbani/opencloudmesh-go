// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"gorm.io/gorm"
)

// Closed terminal-reason tokens, grouped by destination state.
const (
	// Destination terminal_fail.

	// ReasonProbeStartFailed is recorded when the passive probe cannot start.
	ReasonProbeStartFailed = "probe_start_failed"

	// ReasonProbeCompleteFailed is recorded when completing the passive probe fails.
	ReasonProbeCompleteFailed = "probe_complete_failed"

	// ReasonPassiveProbeFailed is recorded when the passive probe itself fails.
	ReasonPassiveProbeFailed = "passive_probe_failed"

	// ReasonCreatedTTLExpired is recorded when a created session outlives its TTL.
	ReasonCreatedTTLExpired = "created_ttl_expired"

	// ReasonPassiveRunningTTLExpired is recorded when a passive_running session
	// outlives its TTL.
	ReasonPassiveRunningTTLExpired = "passive_running_ttl_expired"

	// ReasonPassiveCompleteTTLExpired is recorded when a passive_complete
	// session outlives its TTL.
	ReasonPassiveCompleteTTLExpired = "passive_complete_ttl_expired"

	// ReasonActiveHardFail is the default hard-fail terminal reason.
	ReasonActiveHardFail = "active_hard_fail"

	// ReasonActiveHardFailIdentity is recorded when the identity plane fails
	// the active run.
	ReasonActiveHardFailIdentity = "active_hard_fail_identity"

	// ReasonActiveHardFailDispatch is recorded when designated forward
	// dispatch fails and cannot be retried.
	ReasonActiveHardFailDispatch = "active_hard_fail_dispatch"

	// ReasonActiveHardFailCorrelation is recorded when designated correlation
	// or probe-file binding is gone.
	ReasonActiveHardFailCorrelation = "active_hard_fail_correlation"

	// ReasonOperatorAborted is recorded when the operator aborts the run.
	ReasonOperatorAborted = "operator_aborted"

	// ReasonWrongAccepter is recorded when the accepting peer does not match
	// the session.
	ReasonWrongAccepter = "wrong_accepter"

	// ReasonActiveUnavailable is recorded when active opt-in cannot proceed.
	ReasonActiveUnavailable = "active_unavailable"

	// Destination interrupted.

	// ReasonReverseShareTimeout is recorded when the reverse-share wait
	// outlives its inactivity window.
	ReasonReverseShareTimeout = "reverse_share_timeout"

	// ReasonReverseInviteTimeout is recorded when the reverse-invite wait
	// outlives its inactivity window.
	ReasonReverseInviteTimeout = "reverse_invite_timeout"

	// ReasonStallInactivityExpired is recorded when a stalled non-wait state
	// outlives the inactivity window.
	ReasonStallInactivityExpired = "stall_inactivity_expired"

	// ReasonStartupUnrecoverableActive is recorded when startup recovery
	// interrupts a leftover active run.
	ReasonStartupUnrecoverableActive = "startup_unrecoverable_active"

	// ReasonForwardShareCommitStall is recorded when a recorded forward-share
	// send cannot commit the run forward.
	ReasonForwardShareCommitStall = "forward_share_commit_stall"

	// Destination terminal_pass.

	// ReasonStopped is recorded when the operator stops a complete passive run.
	ReasonStopped = "stopped"

	// ReasonReverseShareObserved is recorded when a timely reverse share
	// passes the active run.
	ReasonReverseShareObserved = "reverse_share_observed"

	// ReasonLateReverseShare is recorded when a reverse share arrives after
	// the wait already timed out.
	ReasonLateReverseShare = "late_reverse_share"
)

const (
	terminalStateOpIn    = "IN"
	terminalStateOpNotIn = "NOT IN"
)

func legalTerminalReasons(state string) []string {
	switch state {
	case StateTerminalFail:
		return slices.Clone([]string{
			ReasonProbeStartFailed,
			ReasonProbeCompleteFailed,
			ReasonPassiveProbeFailed,
			ReasonCreatedTTLExpired,
			ReasonPassiveRunningTTLExpired,
			ReasonPassiveCompleteTTLExpired,
			ReasonActiveHardFail,
			ReasonActiveHardFailIdentity,
			ReasonActiveHardFailDispatch,
			ReasonActiveHardFailCorrelation,
			ReasonOperatorAborted,
			ReasonWrongAccepter,
			ReasonActiveUnavailable,
		})
	case StateInterrupted:
		return slices.Clone([]string{
			ReasonReverseShareTimeout,
			ReasonReverseInviteTimeout,
			ReasonStallInactivityExpired,
			ReasonStartupUnrecoverableActive,
			ReasonForwardShareCommitStall,
		})
	case StateTerminalPass:
		return slices.Clone([]string{
			ReasonStopped,
			ReasonReverseShareObserved,
			ReasonLateReverseShare,
		})
	default:
		return nil
	}
}

func validateTerminalReason(state, reason string) error {
	legal := legalTerminalReasons(state)
	if legal == nil {
		return ErrTerminalStateInvalid
	}

	if !slices.Contains(legal, reason) {
		return fmt.Errorf(
			"validatorcore: terminal reason %q for state %q: %w",
			reason,
			state,
			ErrTerminalReasonInvalid,
		)
	}

	return nil
}

// WriteTerminal is the single first-write terminal writer. One guarded
// UPDATE matches test_run_id, the required active-lock bit, and state IN
// expectedStates, then writes is_active=0, the terminal state, COALESCE
// finished_at, terminal_reason, overall_grade, and updated_at. Permanent
// expiry is sealed in the same transaction. Statistics persist best-effort
// after the state write commits. expectedStates must be a non-empty
// non-terminal set; update.State must be terminal. The guarded seam
// validates the closed terminal-reason set before the UPDATE.
// FlipLateReverseShareToPass and hybrid lock repair do not use this writer.
func (c *Core) WriteTerminal(
	ctx context.Context,
	testRunID string,
	requireActive bool,
	expectedStates []string,
	update ActiveTerminalUpdate,
) error {
	if err := validateActiveTerminalRelease(expectedStates, update.State); err != nil {
		return err
	}

	return c.writeTerminalGuarded(ctx, testRunID, requireActive, terminalStateOpIn, expectedStates, update)
}

func (c *Core) writeTerminalExcept(
	ctx context.Context,
	testRunID string,
	extraExcludedStates []string,
	update ActiveTerminalUpdate,
) error {
	if err := validateActiveTerminalExclusion(extraExcludedStates, update.State); err != nil {
		return err
	}

	excluded := slices.Concat(terminalStateSet(), extraExcludedStates)

	return c.writeTerminalGuarded(ctx, testRunID, true, terminalStateOpNotIn, excluded, update)
}

// writeTerminalGuarded validates the closed terminal-reason set via
// validateTerminalReason(update.State, update.TerminalReason) before the
// UPDATE, after the store-config guard and the wrapper dest-state
// validators. Out-of-set, empty, or whitespace reasons return
// ErrTerminalReasonInvalid (wrapped); a non-terminal dest returns bare
// ErrTerminalStateInvalid.
func (c *Core) writeTerminalGuarded(
	ctx context.Context,
	testRunID string,
	requireActive bool,
	stateOp string,
	states []string,
	update ActiveTerminalUpdate,
) error {
	if c == nil || c.db == nil {
		return errors.New("validatorcore: store is not configured")
	}

	if err := validateTerminalReason(update.State, update.TerminalReason); err != nil {
		return err
	}

	now := time.Now().Unix()
	isActive := boolToInt(requireActive)

	err := c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&TestRun{}).
			Where(
				"test_run_id = ? AND is_active = ? AND state "+stateOp+" ?",
				testRunID,
				isActive,
				states,
			).
			Updates(map[string]any{
				colIsActive:       false,
				colState:          update.State,
				colFinishedAt:     gorm.Expr("COALESCE("+colFinishedAt+", ?)", now),
				colTerminalReason: update.TerminalReason,
				colUpdatedAt:      now,
				colOverallGrade:   update.OverallGrade,
			})
		if res.Error != nil {
			return res.Error
		}

		if res.RowsAffected == 0 {
			return ErrStateTransitionMiss
		}

		return sealTerminalExpiresAt(tx, testRunID, now)
	})
	if err != nil {
		return fmt.Errorf("validatorcore: write terminal: %w", err)
	}

	bestEffortPersistTerminalStats(c, ctx, testRunID)

	return nil
}

// StopPassive terminalizes a core-only passive_complete session. A ready
// opt-in lock waiter is abandoned as terminal_fail with ReasonOperatorAborted.
// A persisted discovery or TLS fail routes to FailPassive; otherwise a
// complete run becomes terminal_pass with a pass or warn grade folded from
// durable evidence. An already-terminal row is a successful no-op so a
// raced second stop can reload the stored state.
func (c *Core) StopPassive(ctx context.Context, testRunID string) error {
	row, err := c.GetTestRun(ctx, testRunID)
	if err != nil {
		return err
	}

	if IsReadyOptInWaiter(row) {
		return c.confirmTerminalAfterMiss(
			ctx,
			testRunID,
			c.FailPassive(ctx, testRunID, StatePassiveRunning, ReasonOperatorAborted),
		)
	}

	areas, err := c.loadPersistedAreaScores(ctx, testRunID)
	if err != nil {
		return err
	}

	if persistedFailPredicate(areas) {
		return c.confirmTerminalAfterMiss(
			ctx,
			testRunID,
			c.FailPassive(ctx, testRunID, StatePassiveComplete, ReasonPassiveProbeFailed),
		)
	}

	grade := stopPassGrade(areas)

	return c.confirmTerminalAfterMiss(
		ctx,
		testRunID,
		c.WriteTerminal(ctx, testRunID, false, []string{StatePassiveComplete}, ActiveTerminalUpdate{
			State:          StateTerminalPass,
			TerminalReason: ReasonStopped,
			OverallGrade:   &grade,
		}),
	)
}

// FailPassive terminalizes a passive session from created, passive_running,
// or passive_complete as terminal_fail with GradeFail. An empty reason is
// rejected and returns ErrTerminalReasonInvalid via the writer seam.
func (c *Core) FailPassive(ctx context.Context, testRunID, expectedState, reason string) error {
	if !isPassiveFailExpectedState(expectedState) {
		return fmt.Errorf("validatorcore: unsupported fail-passive state %q", expectedState)
	}

	grade := GradeFail

	return c.WriteTerminal(ctx, testRunID, false, []string{expectedState}, ActiveTerminalUpdate{
		State:          StateTerminalFail,
		TerminalReason: reason,
		OverallGrade:   &grade,
	})
}

// FailRunTerminal transitions a passive created session directly to terminal_fail.
func (c *Core) FailRunTerminal(ctx context.Context, testRunID, reason string) error {
	return c.FailPassive(ctx, testRunID, StateCreated, reason)
}

// FailPassiveRunningTerminal terminalizes a passive_running session as fail.
func (c *Core) FailPassiveRunningTerminal(ctx context.Context, testRunID, reason string) error {
	return c.FailPassive(ctx, testRunID, StatePassiveRunning, reason)
}

// PassActiveFrom writes terminal_pass from a non-terminal active expected-state
// set. Reverse-share success uses this wrapper; the late flip does not.
func (c *Core) PassActiveFrom(
	ctx context.Context,
	testRunID string,
	expectedStates []string,
	reason string,
) error {
	grade := GradePass

	return c.WriteTerminal(ctx, testRunID, true, expectedStates, ActiveTerminalUpdate{
		State:          StateTerminalPass,
		TerminalReason: reason,
		OverallGrade:   &grade,
	})
}

func (c *Core) confirmTerminalAfterMiss(ctx context.Context, testRunID string, writeErr error) error {
	if writeErr == nil {
		return nil
	}

	if !errors.Is(writeErr, ErrStateTransitionMiss) {
		return writeErr
	}

	row, err := c.GetTestRun(ctx, testRunID)
	if err != nil {
		return err
	}

	if isTerminalState(row.State) {
		return nil
	}

	return writeErr
}

func (c *Core) loadPersistedAreaScores(
	ctx context.Context,
	testRunID string,
) ([]SpecificationAreaScore, error) {
	if c == nil || c.db == nil {
		return nil, errors.New("validatorcore: store is not configured")
	}

	var rows []EvidenceRow

	if err := c.db.WithContext(ctx).
		Where("test_run_id = ?", testRunID).
		Order("created_at ASC, id ASC").
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("validatorcore: load persisted evidence: %w", err)
	}

	if rows == nil {
		rows = []EvidenceRow{}
	}

	return foldSpecificationAreas(rows), nil
}

func isPassiveFailExpectedState(state string) bool {
	switch state {
	case StateCreated, StatePassiveRunning, StatePassiveComplete:
		return true
	default:
		return false
	}
}

func persistedFailPredicate(areas []SpecificationAreaScore) bool {
	for _, area := range areas {
		if !isFailGatedArea(area.Area) {
			continue
		}

		if area.Grade != nil && *area.Grade == GradeFail {
			return true
		}
	}

	return false
}

func isFailGatedArea(area string) bool {
	return area == SpecificationAreaDiscovery || area == SpecificationAreaTLS
}

func stopPassGrade(areas []SpecificationAreaScore) string {
	if hasAreaGrade(areas, GradeWarn) {
		return GradeWarn
	}

	return GradePass
}

func failGatedAreas() []string {
	return []string{SpecificationAreaDiscovery, SpecificationAreaTLS}
}

func failSeverityAliases() []string {
	return []string{GradeFail, "failure", "critical", "error", "fatal"}
}

func notPersistedFailPredicateSQL() string {
	return "NOT EXISTS (SELECT 1 FROM " + tableEvidenceRow +
		" WHERE " + tableEvidenceRow + ".test_run_id = test_run.test_run_id" +
		" AND affects_grade = 1 AND area IN ?" +
		" AND LOWER(" + trimASCIIWhitespaceSQL(tableEvidenceRow+".severity") + ") IN ?)"
}

// trimASCIIWhitespaceSQL matches strings.TrimSpace for ASCII whitespace so a
// stored severity and the promotion CAS grade the same token.
func trimASCIIWhitespaceSQL(expr string) string {
	return "TRIM(" + expr + ", CHAR(9, 10, 11, 12, 13, 32))"
}
