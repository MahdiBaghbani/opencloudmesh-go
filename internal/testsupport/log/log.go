// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package log

import (
	"log/slog"
)

// DiscardLogger returns a logger that discards output at error level or above.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
