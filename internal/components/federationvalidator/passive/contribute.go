// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

// ParseContribute reports whether the scan contribute query parameter opts in.
// Only the literal value "1" opts in; missing, "0", and other values default off.
func ParseContribute(raw string) bool {
	return raw == "1"
}
