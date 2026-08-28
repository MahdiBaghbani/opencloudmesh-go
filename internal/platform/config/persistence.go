// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// Persistence backend name constants. These are the only valid values for
// PersistenceConfig.Backend. Unknown values are rejected at validation time;
// there is no silent fallback to memory.
const (
	BackendMemory = "memory"
	BackendJSON   = "json"
	BackendSQLite = "sqlite"
	BackendMirror = "mirror"
)

// DefaultPersistenceDataDir is the CWD-relative data directory the strict
// preset uses for its durable sqlite backend.
const DefaultPersistenceDataDir = ".ocm/data"

// DefaultValidatorPersistenceDataDir is the CWD-relative data directory the
// validator preset uses for its durable sqlite backend.
const DefaultValidatorPersistenceDataDir = ".ocm/validator-data"

// DefaultContentDir is the CWD-relative managed content root, sibling of the
// default data directory under .ocm/.
const DefaultContentDir = ".ocm/files"

// SeedContentFileName is the demo file created idempotently under the content root.
const SeedContentFileName = "hello-ocm.txt"

// ResolveContentDir returns the absolute path for the managed content root.
// Empty dir falls back to DefaultContentDir relative to the current working
// directory.
func ResolveContentDir(dir string) (string, error) {
	if dir == "" {
		dir = DefaultContentDir
	}

	if !filepath.IsAbs(dir) {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolve content dir: %w", err)
		}

		dir = filepath.Join(cwd, dir)
	}

	return filepath.Clean(dir), nil
}
