// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package dirsync

import (
	"errors"
	"syscall"
	"testing"
)

func TestSyncDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if err := SyncDirectory(dir); err != nil {
		t.Fatalf("SyncDirectory: %v", err)
	}
}

func TestIsUnsupported(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "ErrUnsupported", err: errors.ErrUnsupported, want: true},
		{name: "EINVAL", err: syscall.EINVAL, want: true},
		{name: "ENOSYS", err: syscall.ENOSYS, want: true},
		{name: "ENOTSUP", err: syscall.ENOTSUP, want: true},
		{name: "wrapped EINVAL", err: errors.Join(errors.New("store: sync directory"), syscall.EINVAL), want: true},
		{name: "other", err: errors.New("disk full"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsUnsupported(tt.err); got != tt.want {
				t.Fatalf("IsUnsupported(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestTolerateDirSync(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		if err := TolerateDirSync(dir, SyncDirectory); err != nil {
			t.Fatalf("TolerateDirSync: %v", err)
		}
	})

	t.Run("unsupported", func(t *testing.T) {
		t.Parallel()

		sync := func(string) error {
			return syscall.EINVAL
		}

		if err := TolerateDirSync(dir, sync); err != nil {
			t.Fatalf("TolerateDirSync with EINVAL: %v", err)
		}
	})

	t.Run("real error", func(t *testing.T) {
		t.Parallel()

		sync := func(string) error {
			return errors.New("disk full")
		}

		err := TolerateDirSync(dir, sync)
		if err == nil {
			t.Fatal("TolerateDirSync: want error, got nil")
		}
	})
}
