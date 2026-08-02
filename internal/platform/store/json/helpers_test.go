// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package json_test

import (
	"context"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// rollbackCase is one read-only-dir rollback subtest.
type rollbackCase struct {
	name string
	run  func(t *testing.T, ctx context.Context)
}

// runRollbackSuite drives a save-failure rollback suite: the data directory is
// made read-only in each subtest so saveFile fails, and the subtest verifies
// in-memory state rolled back. Read-only dirs cannot be forced as root.
func runRollbackSuite(t *testing.T, cases []rollbackCase) {
	t.Helper()

	if os.Getuid() == 0 {
		t.Skip("cannot test read-only dir as root")
	}

	ctx := context.Background()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, ctx) })
	}
}

func requireOutgoingShareStore(t *testing.T, d store.Driver) store.OutgoingShareStore {
	t.Helper()

	s, ok := d.(store.OutgoingShareStore)
	if !ok {
		t.Fatal("driver does not implement OutgoingShareStore")
	}

	return s
}

func requireIncomingShareStore(t *testing.T, d store.Driver) store.IncomingShareStore {
	t.Helper()

	s, ok := d.(store.IncomingShareStore)
	if !ok {
		t.Fatal("driver does not implement IncomingShareStore")
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

func restoreDirPerms(t *testing.T, dir string) {
	t.Helper()

	if err := os.Chmod(dir, 0700); err != nil { //nolint:gosec // test helper: restrictive 0700 restores write permission on the temp dir
		t.Fatal(err)
	}
}
