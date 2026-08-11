// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package notifications provides shared OCM notification types and errors.
package notifications

import "errors"

// ErrNotificationsNotAdvertised is returned when the peer discovery document
// does not advertise the notifications capability.
var ErrNotificationsNotAdvertised = errors.New("peer does not advertise notifications capability")
