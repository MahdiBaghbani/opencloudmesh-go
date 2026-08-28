// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"fmt"
)

// Store operation labels for duplicate-key remapping. Remap by operation, never
// by index name.
const (
	OpCreateSessionInsert  = "create_session_insert"
	OpExtendUpdate         = "extend_update"
	OpInsertReportExchange = "insert_report_exchange"
	OpMintOutgoingInvite   = "mint_outgoing_invite"
)

// Public API error codes returned to HTTP clients (409 unless noted).
const (
	CodeSessionNotReady          = "SESSION_NOT_READY"
	CodeInteractiveRunInProgress = "INTERACTIVE_RUN_IN_PROGRESS"
	CodeSessionNotFound          = "SESSION_NOT_FOUND"
	CodeInFlightPassiveLimit     = "IN_FLIGHT_PASSIVE_LIMIT"
	CodeStopSessionMiss          = "STOP_SESSION_MISS"
	CodeAbortRefused             = "ABORT_REFUSED"
	CodeAbortSessionMiss         = "ABORT_SESSION_MISS"
	CodeInviteAlreadyClaimed     = "INVITE_ALREADY_CLAIMED"
)

var (
	// ErrSessionNotReady is returned when a session is not ready for the request.
	ErrSessionNotReady = errors.New(CodeSessionNotReady)

	// ErrSessionNotFound is returned when the requested test run does not exist.
	ErrSessionNotFound = errors.New(CodeSessionNotFound)

	// ErrInFlightPassiveLimit is returned when passive in-flight cap is reached.
	ErrInFlightPassiveLimit = errors.New(CodeInFlightPassiveLimit)

	// ErrStopSessionMiss is returned when stop cannot match passive_complete.
	ErrStopSessionMiss = errors.New(CodeStopSessionMiss)

	// ErrInviteAlreadyClaimed is returned when the session invite was already claimed.
	ErrInviteAlreadyClaimed = errors.New(CodeInviteAlreadyClaimed)

	// ErrStateTransitionMiss is returned when a guarded update affects zero rows.
	ErrStateTransitionMiss = errors.New("state transition miss")

	// ErrTerminalExpectedStatesEmpty is returned when an active terminal
	// release is requested without an expected-state set; empty never means
	// any state.
	ErrTerminalExpectedStatesEmpty = errors.New("terminal expected states empty")

	// ErrTerminalExpectedStatesTerminal is returned when an expected-state set
	// contains a terminal state; expected states are non-terminal pre-images.
	ErrTerminalExpectedStatesTerminal = errors.New("terminal expected states contain terminal state")

	// ErrTerminalStateInvalid is returned when the requested terminal state is
	// not one of terminal_pass, terminal_fail, or interrupted.
	ErrTerminalStateInvalid = errors.New("invalid terminal state")

	// ErrTerminalExclusionTerminal is returned when a terminal release by
	// exclusion names a terminal state in its extra exclusions; the terminal
	// states are always excluded by construction, so naming one is a caller
	// error.
	ErrTerminalExclusionTerminal = errors.New("terminal exclusion contains terminal state")

	// ErrActiveHardFailRefused is returned when a hard-fail carrying a
	// non-identity reason targets a run sitting in one of the graded exercise
	// states; only the identity hard-fail reason may interrupt those.
	ErrActiveHardFailRefused = errors.New("active hard-fail refused in graded exercise state")

	// ErrActiveHardFailReasonInvalid is returned when a hard-fail carries a
	// non-empty reason outside the closed reason set; free-text reasons are
	// rejected before any UPDATE runs.
	ErrActiveHardFailReasonInvalid = errors.New("invalid active hard-fail reason")

	// ErrTerminalReasonInvalid is returned when a terminal reason is not in
	// the closed set for the requested destination state.
	ErrTerminalReasonInvalid = errors.New("invalid terminal reason")

	// ErrInvalidLocalIdentity is returned when a finder local_identity is empty
	// or not a recognized occupancy slot.
	ErrInvalidLocalIdentity = errors.New("invalid local identity")

	// ErrStoreNotConfigured is returned when Core or its DB handle is missing.
	ErrStoreNotConfigured = errors.New("validatorcore: store is not configured")

	// ErrNilTestRun is returned when a rating helper is called with a nil run.
	ErrNilTestRun = errors.New("validatorcore: nil test run")

	// ErrEmptyTestRunID is returned when a rating helper is called without a run id.
	ErrEmptyTestRunID = errors.New("validatorcore: empty test run id")

	// ErrCrossRunRow is returned when a loaded rating row belongs to another run.
	ErrCrossRunRow = errors.New("validatorcore: row does not belong to test run")
)

// StoreError wraps a store failure with the operation that caused it.
type StoreError struct {
	Op  string
	Err error
}

// NewStoreError returns a StoreError for operation-scoped remapping.
func NewStoreError(op string, err error) *StoreError {
	return &StoreError{Op: op, Err: err}
}

func (e *StoreError) Error() string {
	return fmt.Sprintf("validatorcore %s: %v", e.Op, e.Err)
}

func (e *StoreError) Unwrap() error {
	return e.Err
}

// IsActiveSlotBusy reports a one-active unique-index conflict on promote.
func IsActiveSlotBusy(err error) bool {
	var storeErr *StoreError

	return errors.As(err, &storeErr) && storeErr.Op == OpExtendUpdate
}

const (
	colState            = "state"
	colSessionKind      = "session_kind"
	colUpdatedAt        = "updated_at"
	colTestRunID        = "test_run_id"
	colExchangeID       = "exchange_id"
	colCreatedAt        = "created_at"
	colFinishedAt       = "finished_at"
	colTerminalReason   = "terminal_reason"
	colOverallGrade     = "overall_grade"
	colIsActive         = "is_active"
	colBobUserID        = "bob_user_id"
	colOutgoingInviteID = "outgoing_invite_id"
	colRemoteOCMID      = "remote_ocm_id"
	colS1ClaimedAt      = "s1_claimed_at"
	colOptInActive      = "opt_in_active"
	colOptInPermanent   = "opt_in_permanent"
	colOptInStats       = "opt_in_stats"
	colPlatform         = "platform"
	colProviderID       = "provider_id"
	colLocalIdentity    = "local_identity"
	colHostHash         = "host_hash"
	colArea             = "area"
	colStep             = "step"
	colReasonCode       = "reason_code"
	colLeg              = "leg"
)
