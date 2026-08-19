// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/statistics"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

// redactionSaltClaimFileName matches statistics.redactionSaltClaimFileName.
const redactionSaltClaimFileName = "redaction.salt.claim"

func TestBuild_ValidatorUsesSharedSQLiteHandle(t *testing.T) {
	t.Parallel()

	cfg := config.ValidatorConfig()
	cfg.Persistence.DataDir = t.TempDir()

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	t.Cleanup(func() {
		if closeErr := result.Persistence.Close(); closeErr != nil {
			t.Errorf("Persistence.Close: %v", closeErr)
		}
	})

	if result.Deps.ValidatorStore == nil {
		t.Fatal("expected validator store in validator mode")
	}

	sharedDB, err := result.Persistence.SharedDB()
	if err != nil {
		t.Fatalf("SharedDB: %v", err)
	}

	if result.Deps.ValidatorStore.DB() != sharedDB {
		t.Fatal("validator store must attach to the persistence SharedDB handle")
	}

	dbPath := filepath.Join(cfg.Persistence.DataDir, "ocm.db")
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected single ocm.db at %s: %v", dbPath, err)
	}
}

func TestBuild_ValidatorRejectsJSONPersistenceAtBootstrap(t *testing.T) {
	t.Parallel()

	cfg := config.ValidatorConfig()
	cfg.Persistence.Backend = config.BackendJSON
	dataDir := t.TempDir()
	cfg.Persistence.DataDir = dataDir

	_, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err == nil {
		t.Fatal("expected Build to fail for validator mode with json persistence")
	}

	if !errors.Is(err, repos.ErrNoSharedSQLiteHandle) {
		t.Fatalf("Build: expected ErrNoSharedSQLiteHandle, got %v", err)
	}

	assertNoRedactionSaltArtifacts(t, dataDir)
}

func assertNoRedactionSaltArtifacts(t *testing.T, dataDir string) {
	t.Helper()

	saltPath := filepath.Join(dataDir, statistics.RedactionSaltFileName)
	if _, err := os.Stat(saltPath); err == nil {
		t.Fatalf("expected no %s after bootstrap rejection, but file exists", statistics.RedactionSaltFileName)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %s: %v", statistics.RedactionSaltFileName, err)
	}

	claimPath := filepath.Join(dataDir, redactionSaltClaimFileName)
	if _, err := os.Stat(claimPath); err == nil {
		t.Fatalf("expected no %s after bootstrap rejection, but file exists", redactionSaltClaimFileName)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %s: %v", redactionSaltClaimFileName, err)
	}

	tmpPattern := filepath.Join(dataDir, statistics.RedactionSaltFileName+".tmp.*")

	matches, err := filepath.Glob(tmpPattern)
	if err != nil {
		t.Fatalf("glob %s: %v", tmpPattern, err)
	}

	if len(matches) > 0 {
		t.Fatalf("expected no redaction salt temp files after bootstrap rejection, found %v", matches)
	}
}
