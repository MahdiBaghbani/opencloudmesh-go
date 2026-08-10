// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package identity

import "errors"

// IsInfrastructureError reports whether err is an unexpected backend failure rather
// than an expected auth or lookup sentinel (user not found, invalid password,
// session not found, or session expired).
func IsInfrastructureError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, ErrUserNotFound) ||
		errors.Is(err, ErrInvalidPassword) ||
		errors.Is(err, ErrSessionNotFound) ||
		errors.Is(err, ErrSessionExpired) {
		return false
	}

	return true
}
