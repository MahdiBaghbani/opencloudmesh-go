// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package wire holds leaf OCM wire-protocol string constants that the parent
// spec package re-exports. Import this package when spec itself would create
// an import cycle.
package wire

const (
	// CapabilityNotifications is the OCM discovery capability value for notifications.
	CapabilityNotifications = "notifications"
	// ProtocolWebDAV is the OCM discovery protocol role key for WebDAV.
	ProtocolWebDAV = "webdav"
)
