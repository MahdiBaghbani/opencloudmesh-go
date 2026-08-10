// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package dirsync

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"syscall"
)

// SyncDirectory fsyncs a directory after atomic rename.
func SyncDirectory(name string) error {
	dir, err := os.Open(name) //nolint:gosec // G304: name is the parent directory derived from the configured data path and used for directory fsync
	if err != nil {
		return fmt.Errorf("store: open directory for sync: %w", err)
	}

	syncErr := dir.Sync()
	if syncErr != nil {
		//nolint:errcheck // best-effort close after sync failure
		dir.Close()

		return fmt.Errorf("store: sync directory: %w", syncErr)
	}

	if closeErr := dir.Close(); closeErr != nil {
		slog.Warn("directory close after sync failed; ignoring", "dir", name, "err", closeErr)
	}

	return nil
}

// IsUnsupported reports whether err indicates directory fsync is unsupported on this platform.
func IsUnsupported(err error) bool {
	if errors.Is(err, errors.ErrUnsupported) ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOSYS) ||
		errors.Is(err, syscall.ENOTSUP) {
		return true
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		if runtime.GOOS == "windows" && (errno == 1 || errno == 50) {
			return true
		}
	}

	return false
}

// TolerateDirSync runs sync and treats unsupported directory fsync as best-effort.
func TolerateDirSync(name string, sync func(string) error) error {
	if err := sync(name); err != nil {
		if IsUnsupported(err) {
			slog.Warn("directory fsync unsupported; continuing", "dir", name, "err", err)

			return nil
		}

		return fmt.Errorf("failed to sync directory: %w", err)
	}

	return nil
}
