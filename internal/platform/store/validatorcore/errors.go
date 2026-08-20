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
)

// Public API error codes returned to HTTP clients (409 unless noted).
const (
	CodeSessionNotReady          = "SESSION_NOT_READY"
	CodeInteractiveRunInProgress = "INTERACTIVE_RUN_IN_PROGRESS"
	CodeSessionNotFound          = "SESSION_NOT_FOUND"
	CodeInFlightPassiveLimit     = "IN_FLIGHT_PASSIVE_LIMIT"
	CodeStopSessionMiss          = "STOP_SESSION_MISS"
)

var (
	// ErrSessionNotReady is returned when a session is not ready for the request.
	ErrSessionNotReady = errors.New(CodeSessionNotReady)

	// ErrInteractiveRunInProgress is returned when the one-active-run lock is held.
	ErrInteractiveRunInProgress = errors.New(CodeInteractiveRunInProgress)

	// ErrSessionNotFound is returned when the requested test run does not exist.
	ErrSessionNotFound = errors.New(CodeSessionNotFound)

	// ErrInFlightPassiveLimit is returned when passive in-flight cap is reached.
	ErrInFlightPassiveLimit = errors.New(CodeInFlightPassiveLimit)

	// ErrStopSessionMiss is returned when stop cannot match passive_complete.
	ErrStopSessionMiss = errors.New(CodeStopSessionMiss)

	// ErrStateTransitionMiss is returned when a guarded update affects zero rows.
	ErrStateTransitionMiss = errors.New("state transition miss")

	// ErrInvalidStartBody is returned for malformed POST /start bodies.
	ErrInvalidStartBody = errors.New("invalid start request body")

	// ErrInvalidLocalIdentity is returned when a finder local_identity is empty
	// or not a recognized occupancy slot.
	ErrInvalidLocalIdentity = errors.New("invalid local identity")
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

const (
	colState          = "state"
	colSessionKind    = "session_kind"
	colUpdatedAt      = "updated_at"
	colTestRunID      = "test_run_id"
	colExchangeID     = "exchange_id"
	colCreatedAt      = "created_at"
	colFinishedAt     = "finished_at"
	colTerminalReason = "terminal_reason"
	colOverallGrade   = "overall_grade"
	colIsActive       = "is_active"
	colBobUserID      = "bob_user_id"
	colProviderID     = "provider_id"
	colLocalIdentity  = "local_identity"
	colHostHash       = "host_hash"
	colArea           = "area"
)
