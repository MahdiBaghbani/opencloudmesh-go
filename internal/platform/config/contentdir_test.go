// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"path/filepath"
	"testing"
)

func TestResolveContentDir_DefaultRelativeToCWD(t *testing.T) { //nolint:paralleltest // uses t.Chdir
	t.Chdir(t.TempDir())

	got, err := ResolveContentDir("")
	if err != nil {
		t.Fatalf("ResolveContentDir: %v", err)
	}

	cwd, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("Abs cwd: %v", err)
	}

	want := filepath.Join(cwd, DefaultContentDir)
	if got != want {
		t.Fatalf("ResolveContentDir() = %q, want %q", got, want)
	}
}

func TestResolveContentDir_AbsolutePathPassthrough(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	got, err := ResolveContentDir(dir)
	if err != nil {
		t.Fatalf("ResolveContentDir: %v", err)
	}

	want := filepath.Clean(dir)
	if got != want {
		t.Fatalf("ResolveContentDir() = %q, want %q", got, want)
	}
}
