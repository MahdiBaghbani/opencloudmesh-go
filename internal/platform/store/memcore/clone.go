// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package memcore

import "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"

// Clone helpers return copies at value boundaries. IncomingShare carries a
// Requirements slice that must be cloned separately.

func cloneOutgoingShare(s *store.OutgoingShare) *store.OutgoingShare {
	c := *s
	if len(s.Requirements) > 0 {
		c.Requirements = append([]string(nil), s.Requirements...)
	}

	return &c
}

func cloneIncomingShare(s *store.IncomingShare) *store.IncomingShare {
	c := *s
	if len(s.Requirements) > 0 {
		c.Requirements = append([]string(nil), s.Requirements...)
	}

	if len(s.WebappTargets) > 0 {
		c.WebappTargets = append([]string(nil), s.WebappTargets...)
	}

	return &c
}

func cloneOutgoingInvite(i *store.OutgoingInvite) *store.OutgoingInvite {
	c := *i

	return &c
}

func cloneIncomingInvite(i *store.IncomingInvite) *store.IncomingInvite {
	c := *i

	return &c
}
