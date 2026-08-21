// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import "time"

// Grade values stored in stats_raw grade columns.
const (
	GradePass = "pass"
	GradeWarn = "warn"
	GradeFail = "fail"
)

// StatsRaw is one append-only terminal statistics snapshot row. K is the
// keyed-BLAKE3 dedup key for the row; it is NOT NULL and UNIQUE in the schema
// with no database default, so writers must always set it.
type StatsRaw struct {
	ID                     uint    `gorm:"column:id;primaryKey;autoIncrement"`
	K                      string  `gorm:"column:k;not null;uniqueIndex"`
	HostHash               string  `gorm:"column:host_hash;not null;index:idx_stats_raw_host_hash"`
	SessionKind            string  `gorm:"column:session_kind;not null;index:idx_stats_raw_session_kind"`
	ReverseInviteExercised bool    `gorm:"column:reverse_invite_exercised;not null"`
	Platform               string  `gorm:"column:platform;not null;index:idx_stats_raw_platform"`
	APIVersion             string  `gorm:"column:api_version;not null"`
	GradeDiscovery         *string `gorm:"column:grade_discovery"`
	GradeTLS               *string `gorm:"column:grade_tls"`
	GradeJWKS              *string `gorm:"column:grade_jwks"`
	GradeHTTPSig           *string `gorm:"column:grade_httpsig"`
	GradeSharing           *string `gorm:"column:grade_sharing"`
	GradeNotification      *string `gorm:"column:grade_notification"`
	GradeToken             *string `gorm:"column:grade_token"`
	GradeCapability        *string `gorm:"column:grade_capability"`
	CreatedAt              int64   `gorm:"column:created_at;not null;index:idx_stats_raw_created_at"`
}

// TableName returns the GORM table name for StatsRaw.
func (StatsRaw) TableName() string {
	return tableStatsRaw
}

// StatsConnectionReport holds report-only connection detail on the in-memory
// terminal snapshot. It is never copied into stats_raw.
type StatsConnectionReport struct {
	ServerIP      string
	TLSVersion    string
	CipherSuite   string
	CertNotBefore time.Time
	CertNotAfter  time.Time
	CertValid     bool
	LeafCN        string
	LeafSANs      []string
	ReasonCodes   []string
}

// StatsSnapshot is an in-memory terminal snapshot copied into stats_raw. It is
// built from persisted TestRun fields and evidence rows, not a database table.
type StatsSnapshot struct {
	HostHash               string
	SessionKind            string
	ReverseInviteExercised bool
	Platform               string
	APIVersion             string
	GradeDiscovery         *string
	GradeTLS               *string
	GradeJWKS              *string
	GradeHTTPSig           *string
	GradeSharing           *string
	GradeNotification      *string
	GradeToken             *string
	GradeCapability        *string
	CreatedAt              int64
	ConnectionReport       *StatsConnectionReport
}

// ToStatsRaw copies the snapshot into a StatsRaw row.
func (s StatsSnapshot) ToStatsRaw() StatsRaw {
	return StatsRaw{
		HostHash:               s.HostHash,
		SessionKind:            s.SessionKind,
		ReverseInviteExercised: s.ReverseInviteExercised,
		Platform:               s.Platform,
		APIVersion:             s.APIVersion,
		GradeDiscovery:         s.GradeDiscovery,
		GradeTLS:               s.GradeTLS,
		GradeJWKS:              s.GradeJWKS,
		GradeHTTPSig:           s.GradeHTTPSig,
		GradeSharing:           s.GradeSharing,
		GradeNotification:      s.GradeNotification,
		GradeToken:             s.GradeToken,
		GradeCapability:        s.GradeCapability,
		CreatedAt:              s.CreatedAt,
	}
}
