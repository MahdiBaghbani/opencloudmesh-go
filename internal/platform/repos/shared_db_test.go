// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package repos_test

import (
	"context"
	"errors"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
)

func TestSharedDB_SQLiteBackend(t *testing.T) {
	t.Parallel()

	cfg := config.PersistenceConfig{
		Backend: config.BackendSQLite,
		DataDir: t.TempDir(),
	}

	r, err := repos.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Cleanup(func() {
		if closeErr := r.Close(); closeErr != nil {
			t.Errorf("Close: %v", closeErr)
		}
	})

	db, err := r.SharedDB()
	if err != nil {
		t.Fatalf("SharedDB: %v", err)
	}

	if db == nil {
		t.Fatal("SharedDB returned nil handle")
	}
}

func TestSharedDB_MirrorBackend(t *testing.T) {
	t.Parallel()

	cfg := config.PersistenceConfig{
		Backend: config.BackendMirror,
		DataDir: t.TempDir(),
	}

	r, err := repos.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Cleanup(func() {
		if closeErr := r.Close(); closeErr != nil {
			t.Errorf("Close: %v", closeErr)
		}
	})

	db, err := r.SharedDB()
	if err != nil {
		t.Fatalf("SharedDB: %v", err)
	}

	if db == nil {
		t.Fatal("SharedDB returned nil handle")
	}
}

func TestSharedDB_MemoryBackendRejected(t *testing.T) {
	t.Parallel()

	cfg := config.PersistenceConfig{
		Backend: config.BackendMemory,
	}

	r, err := repos.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Cleanup(func() {
		if closeErr := r.Close(); closeErr != nil {
			t.Errorf("Close: %v", closeErr)
		}
	})

	if _, err := r.SharedDB(); err == nil {
		t.Fatal("expected SharedDB to reject memory backend")
	} else if !errors.Is(err, repos.ErrNoSharedSQLiteHandle) {
		t.Fatalf("SharedDB memory backend: expected ErrNoSharedSQLiteHandle, got %v", err)
	}
}

func TestSharedDB_JSONBackendRejected(t *testing.T) {
	t.Parallel()

	cfg := config.PersistenceConfig{
		Backend: config.BackendJSON,
		DataDir: t.TempDir(),
	}

	r, err := repos.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Cleanup(func() {
		if closeErr := r.Close(); closeErr != nil {
			t.Errorf("Close: %v", closeErr)
		}
	})

	if _, err := r.SharedDB(); err == nil {
		t.Fatal("expected SharedDB to reject json backend")
	} else if !errors.Is(err, repos.ErrNoSharedSQLiteHandle) {
		t.Fatalf("SharedDB json backend: expected ErrNoSharedSQLiteHandle, got %v", err)
	}
}
