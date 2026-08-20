// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"

const (
	// ReportVisibilitySession is a live, non-terminal report.
	ReportVisibilitySession = "session"
	// ReportVisibilityPermanent is a terminal opted-in report that has not expired.
	ReportVisibilityPermanent = "permanent"
	// ReportVisibilityExpired is a terminal opted-in report that has expired.
	ReportVisibilityExpired = "expired"
	// ReportVisibilityNotSaved is a terminal report that was not opted in.
	ReportVisibilityNotSaved = "not_saved"
	// ReportVisibilityUnknown is a report id that does not resolve to a row.
	ReportVisibilityUnknown = "unknown"
)

// ClassifyReport maps a test_run row onto the public report visibility set.
func ClassifyReport(row *validatorcore.TestRun, now int64) string {
	if row == nil {
		return ReportVisibilityUnknown
	}

	if !isTerminalReportState(row.State) {
		return ReportVisibilitySession
	}

	if validatorcore.PermanentOptedIn(row) {
		if validatorcore.ReportExpired(row, now) {
			return ReportVisibilityExpired
		}

		return ReportVisibilityPermanent
	}

	return ReportVisibilityNotSaved
}

func isTerminalReportState(state string) bool {
	switch state {
	case validatorcore.StateTerminalPass, validatorcore.StateTerminalFail, validatorcore.StateInterrupted:
		return true
	default:
		return false
	}
}
