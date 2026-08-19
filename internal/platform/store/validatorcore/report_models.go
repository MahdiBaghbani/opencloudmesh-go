// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

// DispatchReservation status values. Status is a reservation lifecycle marker,
// not a TestRun state.
const (
	DispatchStatusReserved = "dispatch_reserved"
)

// ReportExchange is one captured HTTP exchange of a validator session. The
// explicit validator schema DDL is authoritative; GORM tags are column
// mappings only and no AutoMigrate runs for this table.
type ReportExchange struct {
	ExchangeID        uint    `gorm:"column:exchange_id;primaryKey;autoIncrement"`
	TestRunID         string  `gorm:"column:test_run_id;not null;uniqueIndex:idx_report_ex_run_seq,priority:1;index:idx_report_ex_run_captured,priority:1;index:idx_report_ex_run_leg,priority:1;index:idx_report_ex_run_identity,priority:1;index:idx_report_ex_run_endpoint,priority:1;uniqueIndex:idx_report_ex_idem,priority:1,where:request_id IS NOT NULL AND request_id != ''"`
	Seq               int     `gorm:"column:seq;not null;uniqueIndex:idx_report_ex_run_seq,priority:2"`
	CapturedAt        int64   `gorm:"column:captured_at;not null;index:idx_report_ex_run_captured,priority:2"`
	StartedAt         *int64  `gorm:"column:started_at"`
	EndedAt           *int64  `gorm:"column:ended_at"`
	DurationMs        *int64  `gorm:"column:duration_ms"`
	Direction         string  `gorm:"column:direction;not null;uniqueIndex:idx_report_ex_idem,priority:2"`
	Actor             *string `gorm:"column:actor"`
	LocalIdentity     *string `gorm:"column:local_identity;index:idx_report_ex_run_identity,priority:2"`
	CorrRole          *string `gorm:"column:corr_role"`
	Leg               *string `gorm:"column:leg;index:idx_report_ex_run_leg,priority:2"`
	EndpointID        string  `gorm:"column:endpoint_id;not null;index:idx_report_ex_run_endpoint,priority:2"`
	Method            string  `gorm:"column:method;not null"`
	URL               string  `gorm:"column:url;not null"`
	Host              *string `gorm:"column:host"`
	StatusCode        *int    `gorm:"column:status_code"`
	HTTPVersion       *string `gorm:"column:http_version"`
	ErrorText         *string `gorm:"column:error_text"`
	RequestID         *string `gorm:"column:request_id;uniqueIndex:idx_report_ex_idem,priority:3"`
	ReqHeadersJSON    *string `gorm:"column:req_headers_json"`
	RespHeadersJSON   *string `gorm:"column:resp_headers_json"`
	SigRaw            *string `gorm:"column:sig_raw"`
	SigKeyID          *string `gorm:"column:sig_key_id"`
	SigAlgorithm      *string `gorm:"column:sig_algorithm"`
	SigScheme         *string `gorm:"column:sig_scheme"`
	SigValid          *bool   `gorm:"column:sig_valid"`
	Digest            *string `gorm:"column:digest"`
	ReqBodyRedacted   *string `gorm:"column:req_body_redacted"`
	RespBodyRedacted  *string `gorm:"column:resp_body_redacted"`
	ReqBodyRaw        []byte  `gorm:"column:req_body_raw"`
	RespBodyRaw       []byte  `gorm:"column:resp_body_raw"`
	ReqBodySHA256     *string `gorm:"column:req_body_sha256"`
	RespBodySHA256    *string `gorm:"column:resp_body_sha256"`
	ReqBodyBytes      *int64  `gorm:"column:req_body_bytes"`
	RespBodyBytes     *int64  `gorm:"column:resp_body_bytes"`
	ReqBodyTruncated  bool    `gorm:"column:req_body_truncated;not null;default:0"`
	RespBodyTruncated bool    `gorm:"column:resp_body_truncated;not null;default:0"`
	Grade             *string `gorm:"column:grade"`
	ReasonCodes       *string `gorm:"column:reason_codes"`
	CreatedAt         int64   `gorm:"column:created_at;not null"`
}

// TableName returns the GORM table name for ReportExchange.
func (ReportExchange) TableName() string {
	return tableReportExchange
}

// EvidenceRow is one graded or informational evidence entry linked to a
// validator session and optionally to a captured exchange.
type EvidenceRow struct {
	ID              uint    `gorm:"column:id;primaryKey;autoIncrement"`
	TestRunID       string  `gorm:"column:test_run_id;not null;uniqueIndex:idx_evidence_row,priority:1;index:idx_evidence_row_area,priority:1"`
	Area            string  `gorm:"column:area;not null;uniqueIndex:idx_evidence_row,priority:2;index:idx_evidence_row_area,priority:2"`
	Step            string  `gorm:"column:step;not null;uniqueIndex:idx_evidence_row,priority:3"`
	ReasonCode      string  `gorm:"column:reason_code;not null;uniqueIndex:idx_evidence_row,priority:4"`
	Severity        string  `gorm:"column:severity;not null"`
	AffectsGrade    bool    `gorm:"column:affects_grade;not null"`
	PayloadRedacted *string `gorm:"column:payload_redacted"`
	ExchangeID      *uint   `gorm:"column:exchange_id"`
	CreatedAt       int64   `gorm:"column:created_at;not null"`
}

// TableName returns the GORM table name for EvidenceRow.
func (EvidenceRow) TableName() string {
	return tableEvidenceRow
}

// DispatchReservation is the write-once reservation row for a dispatched
// validator session, keyed by test_run_id.
type DispatchReservation struct {
	TestRunID       string  `gorm:"column:test_run_id;primaryKey"`
	ProviderID      string  `gorm:"column:provider_id;not null;uniqueIndex"`
	WebDAVID        string  `gorm:"column:webdav_id;not null;uniqueIndex"`
	SharedSecret    string  `gorm:"column:shared_secret;not null"`
	ReceiverHost    string  `gorm:"column:receiver_host;not null"`
	ShareWith       string  `gorm:"column:share_with;not null"`
	ProbeFilePath   string  `gorm:"column:probe_file_path;not null"`
	Status          string  `gorm:"column:status;not null"`
	OutgoingShareID *string `gorm:"column:outgoing_share_id"`
	RemoteSentAt    *int64  `gorm:"column:remote_sent_at"`
	CASCommittedAt  *int64  `gorm:"column:cas_committed_at"`
	CreatedAt       int64   `gorm:"column:created_at;not null"`
	UpdatedAt       *int64  `gorm:"column:updated_at"`
}

// TableName returns the GORM table name for DispatchReservation.
func (DispatchReservation) TableName() string {
	return tableDispatchReservation
}
