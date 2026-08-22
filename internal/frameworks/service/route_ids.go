// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package service

const (
	// RouteIDOCMToken is the OCM token route identifier.
	RouteIDOCMToken = "ocm-token"
	// RouteIDWebDAVOCMWildcard is the WebDAV OCM wildcard route identifier.
	RouteIDWebDAVOCMWildcard = "webdav-ocm-wildcard"
	// RouteIDUIAcceptInvite is the UI accept-invite route identifier.
	RouteIDUIAcceptInvite = "ui-accept-invite"
	// RouteIDUIWAYF is the UI WAYF route identifier.
	RouteIDUIWAYF = "ui-wayf"
	// RouteIDAPIHealthz is the API health check route identifier.
	RouteIDAPIHealthz = "api-healthz"
	// RouteIDValidatorAPIStatistics is the validator statistics route identifier.
	RouteIDValidatorAPIStatistics = "validator-api-statistics"
	// RouteIDValidatorAPISession is the validator session polling route identifier.
	RouteIDValidatorAPISession = "validator-api-session"
	// RouteIDValidatorAPISessionInvite is the validator session invite-claim route identifier.
	RouteIDValidatorAPISessionInvite = "validator-api-session-invite"
	// RouteIDValidatorAPISessionReverseInvite is the validator reverse-invite paste route identifier.
	RouteIDValidatorAPISessionReverseInvite = "validator-api-session-reverse-invite"
	// RouteIDValidatorAPIReport is the validator JSON report route identifier.
	RouteIDValidatorAPIReport = "validator-api-report"
	// RouteIDValidatorHTMLReport is the validator HTML report route identifier.
	RouteIDValidatorHTMLReport = "validator-html-report"
	// RouteIDValidatorAPIReportRetention is the validator report retention PATCH identifier.
	RouteIDValidatorAPIReportRetention = "validator-api-report-retention"
	// RouteIDValidatorAPIReportLock is the validator report lock POST identifier.
	RouteIDValidatorAPIReportLock = "validator-api-report-lock"
)

const subtreeDefaultIDSuffix = "-subtree-default"

// SubtreeDefaultID returns the synthetic subtree route ID for a service name.
func SubtreeDefaultID(serviceName string) string {
	return serviceName + subtreeDefaultIDSuffix
}
