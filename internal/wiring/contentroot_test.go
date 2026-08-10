// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func TestBuild_EnsuresContentRootAndSeedFile(t *testing.T) { //nolint:paralleltest // uses t.Chdir
	t.Chdir(t.TempDir())

	cfg := config.DevConfig()

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	t.Cleanup(func() {
		if cerr := result.Persistence.Close(); cerr != nil {
			t.Errorf("Persistence.Close(): %v", cerr)
		}
	})

	root, err := config.ResolveContentDir(cfg.Persistence.ContentDir)
	if err != nil {
		t.Fatalf("ResolveContentDir: %v", err)
	}

	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("content root stat: %v", err)
	}

	if !info.IsDir() {
		t.Fatalf("content root %q is not a directory", root)
	}

	if info.Mode().Perm() != 0700 {
		t.Errorf("content root mode = %o, want 0700", info.Mode().Perm())
	}

	seedPath := filepath.Join(root, config.SeedContentFileName)

	seedData, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatalf("read seed file: %v", err)
	}

	if !strings.Contains(string(seedData), "Hello from OpenCloudMesh Go reference.") {
		t.Fatalf("seed file missing expected greeting: %q", string(seedData))
	}

	seedInfo, err := os.Stat(seedPath)
	if err != nil {
		t.Fatalf("stat seed file: %v", err)
	}

	if seedInfo.Mode().Perm() != 0600 {
		t.Errorf("seed file mode = %o, want 0600", seedInfo.Mode().Perm())
	}
}

func TestBuild_ContentRootSeedFileIsIdempotent(t *testing.T) { //nolint:paralleltest // uses t.Chdir
	t.Chdir(t.TempDir())

	cfg := config.DevConfig()
	customSeed := "operator-owned seed content\n"

	root, err := config.ResolveContentDir(cfg.Persistence.ContentDir)
	if err != nil {
		t.Fatalf("ResolveContentDir: %v", err)
	}

	if err = os.MkdirAll(root, 0700); err != nil {
		t.Fatalf("MkdirAll content root: %v", err)
	}

	seedPath := filepath.Join(root, config.SeedContentFileName)
	if err = os.WriteFile(seedPath, []byte(customSeed), 0600); err != nil {
		t.Fatalf("write custom seed: %v", err)
	}

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	t.Cleanup(func() {
		if cerr := result.Persistence.Close(); cerr != nil {
			t.Errorf("Persistence.Close(): %v", cerr)
		}
	})

	seedData, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatalf("read seed file: %v", err)
	}

	if string(seedData) != customSeed {
		t.Fatalf("seed file overwritten: got %q, want %q", string(seedData), customSeed)
	}
}
