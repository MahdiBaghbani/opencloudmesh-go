// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package spec

// Canonical OCM discovery capability wire values (IETF-RFC / OpenAPI).
//
// Invites dual-plane: outbound.EndpointInvites is an endpoint/type-plane
// concept for outbound POST targets, while CapabilityInvite is the discovery
// wire capability value. Keep those planes distinct even when the literal
// string coincides.
const (
	CapabilityHTTPSig       = "http-sig"
	CapabilityExchangeToken = "exchange-token"
	CapabilityInvite        = "invites"
	CapabilityInviteWAYF    = "invite-wayf"
	CapabilityNotifications = "notifications"
)
