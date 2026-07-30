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

// OutgoingShareStatus tracks the lifecycle state of an outgoing share (sent, accepted, declined).
type OutgoingShareStatus string

const (
	// OutgoingShareStatusSent is the sent share status.
	OutgoingShareStatusSent OutgoingShareStatus = "sent"
	// OutgoingShareStatusAccepted is the accepted share status.
	OutgoingShareStatusAccepted OutgoingShareStatus = "accepted"
	// OutgoingShareStatusDeclined is the declined share status.
	OutgoingShareStatusDeclined OutgoingShareStatus = "declined"
)
