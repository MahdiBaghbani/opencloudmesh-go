// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

var seedHookMu sync.Mutex

func lockSeedHooks(t *testing.T) {
	t.Helper()
	seedHookMu.Lock()
	t.Cleanup(seedHookMu.Unlock)
}

func TestWriteExclusiveSeedFile_RemovesPartialOnWriteError(t *testing.T) {
	t.Parallel()
	lockSeedHooks(t)

	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.txt")

	oldWrite := seedFileWrite

	t.Cleanup(func() { seedFileWrite = oldWrite })

	seedFileWrite = func(_ *os.File, _ []byte) (int, error) {
		return 0, errors.New("injected write failure")
	}

	if err := writeExclusiveSeedFile(seedPath, []byte("seed")); err == nil {
		t.Fatal("expected write error")
	}

	if _, err := os.Stat(seedPath); !os.IsNotExist(err) {
		t.Fatalf("partial seed file should be removed after write error, stat err=%v", err)
	}
}

func TestWriteExclusiveSeedFile_RemovesPartialOnCloseError(t *testing.T) {
	t.Parallel()
	lockSeedHooks(t)

	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.txt")

	oldClose := seedFileClose

	t.Cleanup(func() { seedFileClose = oldClose })

	seedFileClose = func(_ *os.File) error {
		return errors.New("injected close failure")
	}

	if err := writeExclusiveSeedFile(seedPath, []byte("seed")); err == nil {
		t.Fatal("expected close error")
	}

	if _, err := os.Stat(seedPath); !os.IsNotExist(err) {
		t.Fatalf("partial seed file should be removed after close error, stat err=%v", err)
	}
}

func TestWriteExclusiveSeedFile_RetryAfterWriteError(t *testing.T) {
	t.Parallel()
	lockSeedHooks(t)

	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.txt")
	content := []byte("seed content")

	oldWrite := seedFileWrite

	t.Cleanup(func() { seedFileWrite = oldWrite })

	failWrite := true
	seedFileWrite = func(f *os.File, b []byte) (int, error) {
		if failWrite {
			return 0, errors.New("injected write failure")
		}

		return f.Write(b)
	}

	if err := writeExclusiveSeedFile(seedPath, content); err == nil {
		t.Fatal("expected first write attempt to fail")
	}

	if _, err := os.Stat(seedPath); !os.IsNotExist(err) {
		t.Fatalf("partial seed file should be removed before retry, stat err=%v", err)
	}

	failWrite = false

	if err := writeExclusiveSeedFile(seedPath, content); err != nil {
		t.Fatalf("retry after cleanup: %v", err)
	}

	got, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatalf("read seed after retry: %v", err)
	}

	if string(got) != string(content) {
		t.Fatalf("seed content = %q, want %q", got, content)
	}
}
