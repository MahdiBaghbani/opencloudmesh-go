// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package shares provides shared share lifecycle enums used by the incoming
// and outgoing share packages.
package shares

// ShareStatus tracks the lifecycle state of an incoming share (pending, accepted, declined).
type ShareStatus string

const (
	// ShareStatusPending is the pending share status.
	ShareStatusPending ShareStatus = "pending"
	// ShareStatusAccepted is the accepted share status.
	ShareStatusAccepted ShareStatus = "accepted"
	// ShareStatusDeclined is the declined share status.
	ShareStatusDeclined ShareStatus = "declined"
)

// OutgoingShareStatus tracks the lifecycle state of an outgoing share (pending, sent, accepted, declined, failed).
type OutgoingShareStatus string

const (
	// OutgoingShareStatusSent is the sent share status.
	OutgoingShareStatusSent OutgoingShareStatus = "sent"
	// OutgoingShareStatusAccepted is the accepted share status.
	OutgoingShareStatusAccepted OutgoingShareStatus = "accepted"
	// OutgoingShareStatusDeclined is the declined share status.
	OutgoingShareStatusDeclined OutgoingShareStatus = "declined"
	// OutgoingShareStatusPending is the pending share status (persisted, not yet delivered).
	OutgoingShareStatusPending OutgoingShareStatus = "pending"
	// OutgoingShareStatusFailed is the failed share status (delivery failed; record kept for audit).
	OutgoingShareStatusFailed OutgoingShareStatus = "failed"
)
