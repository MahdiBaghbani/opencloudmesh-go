// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package modroot

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// ModuleRoot returns the directory containing go.mod by walking up from the
// immediate caller's source file.
//
// The lookup resolves the caller source path via runtime.Caller, so it is
// independent of the process working directory. This keeps it safe when tests
// use t.Parallel or otherwise mutate the process-global CWD (os.Chdir)
// concurrently.
func ModuleRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(1)
	if !ok {
		t.Fatal("modroot: could not determine caller source file")
	}

	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find module root (go.mod)")
		}

		dir = parent
	}
}
