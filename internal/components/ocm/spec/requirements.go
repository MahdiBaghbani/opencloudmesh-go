// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package spec

// Canonical OCM protocol requirement wire values (IETF-RFC / OpenAPI).
// Used on share WebDAV/webapp arms and by access/admission call sites.
const (
	RequirementMustExchangeToken = "must-exchange-token"

	// RequirementMustUseMFA is recognized only to be hard-rejected at admit;
	// MFA enforcement is not supported.
	RequirementMustUseMFA = "must-use-mfa"
)
