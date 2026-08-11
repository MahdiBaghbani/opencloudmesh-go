// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package outbound

// EndpointKind classifies outbound OCM POST targets for signing policy.
type EndpointKind string

const (
	// EndpointShares is the shares outbound endpoint kind.
	EndpointShares EndpointKind = "shares"
	// EndpointInvites is the invites outbound endpoint kind.
	EndpointInvites EndpointKind = "invites"
	// EndpointNotifications is the notifications outbound endpoint kind.
	EndpointNotifications EndpointKind = "notifications"
)
