// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

// SessionKind values for TestRun and stats_raw.session_kind.
const (
	SessionKindPassiveOnly = "passive_only"
	SessionKindActiveFull  = "active_full"
)

// TestRun state values (17-value session state enum). Forward sub-progress stays
// on step or coordinator labels, not on State.
//
// Reverse states (reverse_invite_solicited through reverse_capability_exercise)
// are defined for the reverse-plane open window but intentionally dormant and
// unreachable until reverse-plane wiring lands.
const (
	StateCreated                   = "created"
	StatePassiveRunning            = "passive_running"
	StatePassiveComplete           = "passive_complete"
	StateActiveRunning             = "active_running"
	StateInviteMinted              = "invite_minted"
	StateAwaitingReturnShare       = "awaiting_return_share"
	StateCapabilityExercise        = "capability_exercise"
	StateReverseInviteSolicited    = "reverse_invite_solicited"
	StateReverseAwaitingInvite     = "reverse_awaiting_invite"
	StateReverseInviteImported     = "reverse_invite_imported"
	StateReverseInviteAccepted     = "reverse_invite_accepted"
	StateReverseAwaitingShare      = "reverse_awaiting_share"
	StateReverseShareAccepted      = "reverse_share_accepted"
	StateReverseCapabilityExercise = "reverse_capability_exercise"
	StatePassiveDone               = "passive_done"
	StateTerminalPass              = "terminal_pass"
	StateTerminalFail              = "terminal_fail"
)

// ShareCorrelation role values. sender_host is the TARGET authority for all four
// roles (the authority advertised by the target discovery document), not an
// operator alias and not identity B as sender.
const (
	RoleOutgoingToTarget   = "outgoing_to_target"
	RoleIncomingFromTarget = "incoming_from_target"
	RoleOutgoingInvite     = "outgoing_invite"
	RoleIncomingInvite     = "incoming_invite"
)

// ShareCorrelation status values.
const (
	CorrelationStatusPending   = "pending"
	CorrelationStatusConfirmed = "confirmed"
)

// LocalIdentity values for share_correlation.local_identity.
const (
	LocalIdentityA = "a"
	LocalIdentityB = "b"
)

// TestRun is the federation validator session persistence model.
type TestRun struct {
	TestRunID      string  `gorm:"column:test_run_id;primaryKey"`
	IsActive       bool    `gorm:"column:is_active;uniqueIndex:idx_test_run_one_active,where:is_active = 1"`
	State          string  `gorm:"column:state;index"`
	TargetOrigin   string  `gorm:"column:target_origin"`
	TargetHost     string  `gorm:"column:target_host"` // target authority from target discovery, not an operator alias
	DiscoveryURL   string  `gorm:"column:discovery_url"`
	JwksURI        string  `gorm:"column:jwks_uri"`
	TerminalReason *string `gorm:"column:terminal_reason"`
	FinishedAt     *int64  `gorm:"column:finished_at"`
	OverallGrade   *string `gorm:"column:overall_grade"`
	ManifestSchema string  `gorm:"column:manifest_schema"`
	ManifestJSON   *string `gorm:"column:manifest_json"`
	SessionKind    string  `gorm:"column:session_kind;index"` // passive_only | active_full
	CreatedAt      int64   `gorm:"column:created_at"`
	UpdatedAt      int64   `gorm:"column:updated_at"`
}

// TableName returns the GORM table name for TestRun.
func (TestRun) TableName() string {
	return "test_run"
}

// ShareCorrelation links validator session evidence to OCM share and invite ids.
type ShareCorrelation struct {
	ID            uint    `gorm:"column:id;primaryKey;autoIncrement"`
	TestRunID     string  `gorm:"column:test_run_id;uniqueIndex:idx_share_corr_unique,priority:1"`
	Role          string  `gorm:"column:role;uniqueIndex:idx_share_corr_unique,priority:2"`
	SenderHost    string  `gorm:"column:sender_host;uniqueIndex:idx_share_corr_unique,priority:3"`
	ProviderID    string  `gorm:"column:provider_id;uniqueIndex:idx_share_corr_unique,priority:4"`
	LocalIdentity string  `gorm:"column:local_identity;uniqueIndex:idx_share_corr_unique,priority:5;default:a"`
	ShareID       *string `gorm:"column:share_id"`
	InviteID      *string `gorm:"column:invite_id"`
	Status        string  `gorm:"column:status;not null;default:confirmed"`
	CreatedAt     int64   `gorm:"column:created_at"`
}

// TableName returns the GORM table name for ShareCorrelation.
func (ShareCorrelation) TableName() string {
	return "share_correlation"
}
