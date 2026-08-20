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

// Opt-in create channels recorded on TestRun when a consent is selected.
const (
	OptInChannelStart = "start"
	OptInChannelScan  = "scan"
)

// TestRun state values (16-value session state enum). Forward and reverse
// sub-progress live on State as granular values, and the reverse states are
// reachable session states, not dormant placeholders. The test_run.state CHECK
// constraint in the validator schema lists exactly these values.
const (
	StateCreated                = "created"
	StatePassiveRunning         = "passive_running"
	StatePassiveComplete        = "passive_complete"
	StateActiveRunning          = "active_running"
	StateInviteMinted           = "invite_minted"
	StateInviteAccepted         = "invite_accepted"
	StateForwardShareSent       = "forward_share_sent"
	StateCapabilityExercise     = "capability_exercise"
	StateReverseInviteSolicited = "reverse_invite_solicited"
	StateReverseAwaitingInvite  = "reverse_awaiting_invite"
	StateReverseInviteImported  = "reverse_invite_imported"
	StateReverseInviteAccepted  = "reverse_invite_accepted"
	StateReverseAwaitingShare   = "reverse_awaiting_share"
	StateTerminalPass           = "terminal_pass"
	StateTerminalFail           = "terminal_fail"
	StateInterrupted            = "interrupted"
)

// Dormant session state values reserved for the reverse-return lifecycle.
// They sit off the reachable graph: no guarded transition writes them and the
// schema state set excludes them, so no session row can hold these values yet.
const (
	StateAwaitingReturnShare       = "awaiting_return_share"
	StatePassiveDone               = "passive_done"
	StateReverseShareAccepted      = "reverse_share_accepted"
	StateReverseCapabilityExercise = "reverse_capability_exercise"
)

// testRunStates lists every allowed test_run.state value. The validator schema
// CHECK constraint and the version-1 runtime validation use exactly this set.
var testRunStates = []string{
	StateCreated,
	StatePassiveRunning,
	StatePassiveComplete,
	StateActiveRunning,
	StateInviteMinted,
	StateInviteAccepted,
	StateForwardShareSent,
	StateCapabilityExercise,
	StateReverseInviteSolicited,
	StateReverseAwaitingInvite,
	StateReverseInviteImported,
	StateReverseInviteAccepted,
	StateReverseAwaitingShare,
	StateTerminalPass,
	StateTerminalFail,
	StateInterrupted,
}

// NextInstructionForState maps a session state to the stable nextInstruction
// key published by session polling. A key tells the operator what the flow
// waits on next and carries no session secrets. Terminal, dormant, and unknown
// states return an empty string so poll responses omit the key.
func NextInstructionForState(state string) string {
	switch state {
	case StateCreated, StatePassiveRunning:
		return "wait_probe"
	case StatePassiveComplete:
		return "extend_or_stop"
	case StateActiveRunning:
		return "wait_invite_mint"
	case StateInviteMinted:
		return "paste_s1"
	case StateInviteAccepted:
		return "wait_reverse_start"
	case StateReverseInviteSolicited:
		return "wait_reverse_invite"
	case StateReverseAwaitingInvite:
		return "paste_s2"
	case StateReverseInviteImported:
		return "wait_reverse_accept"
	case StateReverseInviteAccepted:
		return "wait_forward_share"
	case StateForwardShareSent:
		return "open_forward_file"
	case StateCapabilityExercise:
		return "wait_oq2_open"
	case StateReverseAwaitingShare:
		return "wait_reverse_share_or_timeout"
	default:
		return ""
	}
}

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

// TestRun is the federation validator session persistence model. The explicit
// validator schema DDL is authoritative; GORM tags are column mappings only.
type TestRun struct {
	TestRunID      string  `gorm:"column:test_run_id;primaryKey"`
	IsActive       bool    `gorm:"column:is_active;not null;uniqueIndex:idx_test_run_one_active,where:is_active = 1"`
	State          string  `gorm:"column:state;not null;index:idx_test_run_state"`
	TargetOrigin   string  `gorm:"column:target_origin;not null"`
	TargetHost     string  `gorm:"column:target_host;not null"` // target authority from target discovery, not an operator alias
	DiscoveryURL   string  `gorm:"column:discovery_url;not null"`
	JwksURI        string  `gorm:"column:jwks_uri;not null"`
	TerminalReason *string `gorm:"column:terminal_reason"`
	FinishedAt     *int64  `gorm:"column:finished_at"`
	OverallGrade   *string `gorm:"column:overall_grade"`
	ManifestSchema string  `gorm:"column:manifest_schema;not null"`
	ManifestJSON   *string `gorm:"column:manifest_json"`
	SessionKind    string  `gorm:"column:session_kind;not null;index:idx_test_run_session_kind"` // passive_only | active_full

	// Reverse-plane, consent, and retention fields. Nullable until the
	// corresponding lifecycle step records them.
	BobUserID                   *string `gorm:"column:bob_user_id;index:idx_test_run_bob_user_id"`
	ReverseInviteToken          *string `gorm:"column:reverse_invite_token"`
	ReverseInviteImportedAt     *int64  `gorm:"column:reverse_invite_imported_at"`
	DesignatedShareWith         *string `gorm:"column:designated_share_with"`
	ReverseShareProviderID      *string `gorm:"column:reverse_share_provider_id"`
	StatsWrittenAt              *int64  `gorm:"column:stats_written_at;index:idx_test_run_stats_heal,where:opt_in_stats = 1 AND stats_written_at IS NULL"`
	OptInStats                  bool    `gorm:"column:opt_in_stats;not null;default:0"`
	OptInPermanent              bool    `gorm:"column:opt_in_permanent;not null;default:0"`
	OptInStatsChannel           *string `gorm:"column:opt_in_stats_channel"`
	OptInStatsAt                *int64  `gorm:"column:opt_in_stats_at"`
	OptInPermanentChannel       *string `gorm:"column:opt_in_permanent_channel"`
	OptInPermanentAt            *int64  `gorm:"column:opt_in_permanent_at"`
	RetentionTier               *string `gorm:"column:retention_tier"`
	RetentionLockedAt           *int64  `gorm:"column:retention_locked_at"`
	ExpiresAt                   *int64  `gorm:"column:expires_at;index:idx_test_run_expires_at"`
	PermanentReportID           *string `gorm:"column:permanent_report_id;uniqueIndex"`
	HarvestedAt                 *int64  `gorm:"column:harvested_at"`
	HarvestedSessionArtifactsAt *int64  `gorm:"column:harvested_session_artifacts_at"`
	HarvestReason               *string `gorm:"column:harvest_reason"`

	CreatedAt int64 `gorm:"column:created_at;not null"`
	UpdatedAt int64 `gorm:"column:updated_at;not null"`
}

// TableName returns the GORM table name for TestRun.
func (TestRun) TableName() string {
	return tableTestRun
}

// ShareCorrelation links validator session evidence to OCM share and invite ids.
type ShareCorrelation struct {
	ID            uint    `gorm:"column:id;primaryKey;autoIncrement"`
	TestRunID     string  `gorm:"column:test_run_id;not null;uniqueIndex:idx_share_corr_unique,priority:1;uniqueIndex:idx_share_corr_outgoing_invite_slot,where:role = 'outgoing_invite';uniqueIndex:idx_share_corr_incoming_invite_slot,where:role = 'incoming_invite'"`
	Role          string  `gorm:"column:role;not null;uniqueIndex:idx_share_corr_unique,priority:2"`
	SenderHost    string  `gorm:"column:sender_host;not null;uniqueIndex:idx_share_corr_unique,priority:3"`
	ProviderID    string  `gorm:"column:provider_id;not null;uniqueIndex:idx_share_corr_unique,priority:4"`
	LocalIdentity string  `gorm:"column:local_identity;not null;uniqueIndex:idx_share_corr_unique,priority:5"`
	ShareID       *string `gorm:"column:share_id"`
	InviteID      *string `gorm:"column:invite_id"`
	Status        string  `gorm:"column:status;not null;default:confirmed"`
	CreatedAt     int64   `gorm:"column:created_at;not null"`
}

// TableName returns the GORM table name for ShareCorrelation.
func (ShareCorrelation) TableName() string {
	return tableShareCorrelation
}
