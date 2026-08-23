// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package catalog is the validator route and capability SSOT. Passive and the
// validator service project from it; this package does not import either.
package catalog

// Caps records which validator legs are present for mount and advertisement.
type Caps struct {
	Runner        bool
	ReverseInvite bool
	ForwardShare  bool
	ReverseShare  bool
	Abort         bool
}

// ReverseInviteAvailable reports the reverse-invite paste and claim path:
// runner, reverse-invite, forward-share, and reverse-share must all be present.
func (c Caps) ReverseInviteAvailable() bool {
	return c.Runner && c.ReverseInvite && c.ForwardShare && c.ReverseShare
}

// FullCaps returns every capability flag set. Tests use it for the complete
// mount and advertisement walk.
func FullCaps() Caps {
	return Caps{
		Runner:        true,
		ReverseInvite: true,
		ForwardShare:  true,
		ReverseShare:  true,
		Abort:         true,
	}
}
