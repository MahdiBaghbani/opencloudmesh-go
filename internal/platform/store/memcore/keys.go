// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package memcore

// providerKey creates a lookup key for incoming shares.
func providerKey(senderHost, providerID string) string {
	return senderHost + ":" + providerID
}

// tokenUserKey creates a lookup key for incoming invites scoped to a recipient.
func tokenUserKey(token, recipientUserID string) string {
	return token + "\x00" + recipientUserID
}
