// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package mirror_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

func requireOutgoingShareStore(t *testing.T, d store.Driver) store.OutgoingShareStore {
	t.Helper()

	s, ok := d.(store.OutgoingShareStore)
	if !ok {
		t.Fatal("driver does not implement OutgoingShareStore")
	}

	return s
}

func requireOutgoingInviteStore(t *testing.T, d store.Driver) store.OutgoingInviteStore {
	t.Helper()

	s, ok := d.(store.OutgoingInviteStore)
	if !ok {
		t.Fatal("driver does not implement OutgoingInviteStore")
	}

	return s
}

func requireIncomingInviteStore(t *testing.T, d store.Driver) store.IncomingInviteStore {
	t.Helper()

	s, ok := d.(store.IncomingInviteStore)
	if !ok {
		t.Fatal("driver does not implement IncomingInviteStore")
	}

	return s
}
