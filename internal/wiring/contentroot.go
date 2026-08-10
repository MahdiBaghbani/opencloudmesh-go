// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

const seedContentBody = `Hello from OpenCloudMesh Go reference.

This sample file lives in the managed content root.
Share it through the outgoing shares API without typing a raw OS path.
`

func ensureContentRoot(cfg *config.Config) error {
	root, err := config.ResolveContentDir(cfg.Persistence.ContentDir)
	if err != nil {
		return fmt.Errorf("resolve content directory: %w", err)
	}

	if err := os.MkdirAll(root, 0700); err != nil {
		return fmt.Errorf("create content directory %q: %w", root, err)
	}

	seedPath := filepath.Join(root, config.SeedContentFileName)
	if err := writeExclusiveSeedFile(seedPath, []byte(seedContentBody)); err != nil {
		if os.IsExist(err) {
			return nil
		}

		return fmt.Errorf("create seed file %q: %w", seedPath, err)
	}

	return nil
}

func writeExclusiveSeedFile(seedPath string, content []byte) error {
	//nolint:gosec // seedPath is under the resolved managed content root, not request-derived input
	seedFile, err := os.OpenFile(seedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if os.IsExist(err) {
			return err //nolint:wrapcheck // preserve os.IsExist for idempotent seed creation
		}

		return fmt.Errorf("open seed file %q: %w", seedPath, err)
	}

	if _, err := seedFileWrite(seedFile, content); err != nil {
		closeErr := seedFileClose(seedFile)

		removePartialSeedFile(seedPath)

		if closeErr != nil {
			return fmt.Errorf("write seed file %q: %w (close: %w)", seedPath, err, closeErr)
		}

		return fmt.Errorf("write seed file %q: %w", seedPath, err)
	}

	if err := seedFileClose(seedFile); err != nil {
		removePartialSeedFile(seedPath)

		return fmt.Errorf("close seed file %q: %w", seedPath, err)
	}

	return nil
}

func removePartialSeedFile(path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		_ = err // best-effort cleanup; non-not-exist errors are intentionally ignored
	}
}

var (
	seedFileWrite = func(f *os.File, content []byte) (int, error) { return f.Write(content) }
	seedFileClose = func(f *os.File) error { return f.Close() }
)
