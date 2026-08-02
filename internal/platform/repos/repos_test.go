// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package repos_test

import (
	"context"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

// ---- backend selection ----

func TestNew_MemoryBackend(t *testing.T) {
	ctx := context.Background()
	cfg := config.PersistenceConfig{Backend: config.BackendMemory}

	r, err := repos.New(ctx, cfg)
	if err != nil {
		t.Fatalf("New(memory) error = %v", err)
	}
	defer tshttp.MustClose(t, r)

	if r.OutgoingShares == nil {
		t.Error("OutgoingShares is nil")
	}

	if r.IncomingShares == nil {
		t.Error("IncomingShares is nil")
	}

	if r.OutgoingInvites == nil {
		t.Error("OutgoingInvites is nil")
	}

	if r.IncomingInvites == nil {
		t.Error("IncomingInvites is nil")
	}
}

func TestNew_JSONBackend(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	cfg := config.PersistenceConfig{
		Backend: config.BackendJSON,
		DataDir: dir,
	}

	r, err := repos.New(ctx, cfg)
	if err != nil {
		t.Fatalf("New(json) error = %v", err)
	}
	defer tshttp.MustClose(t, r)

	if r.OutgoingShares == nil {
		t.Error("OutgoingShares is nil")
	}

	if r.IncomingShares == nil {
		t.Error("IncomingShares is nil")
	}

	if r.OutgoingInvites == nil {
		t.Error("OutgoingInvites is nil")
	}

	if r.IncomingInvites == nil {
		t.Error("IncomingInvites is nil")
	}
}

func TestNew_SQLiteBackend(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	cfg := config.PersistenceConfig{
		Backend: config.BackendSQLite,
		DataDir: dir,
	}

	r, err := repos.New(ctx, cfg)
	if err != nil {
		t.Fatalf("New(sqlite) error = %v", err)
	}
	defer tshttp.MustClose(t, r)

	if r.OutgoingShares == nil {
		t.Error("OutgoingShares is nil")
	}

	if r.IncomingShares == nil {
		t.Error("IncomingShares is nil")
	}

	if r.OutgoingInvites == nil {
		t.Error("OutgoingInvites is nil")
	}

	if r.IncomingInvites == nil {
		t.Error("IncomingInvites is nil")
	}
}

func TestNew_MirrorBackend(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	cfg := config.PersistenceConfig{
		Backend: config.BackendMirror,
		DataDir: dir,
	}

	r, err := repos.New(ctx, cfg)
	if err != nil {
		t.Fatalf("New(mirror) error = %v", err)
	}
	defer tshttp.MustClose(t, r)

	if r.OutgoingShares == nil {
		t.Error("OutgoingShares is nil")
	}

	if r.IncomingShares == nil {
		t.Error("IncomingShares is nil")
	}

	if r.OutgoingInvites == nil {
		t.Error("OutgoingInvites is nil")
	}

	if r.IncomingInvites == nil {
		t.Error("IncomingInvites is nil")
	}
}

func TestNew_UnknownBackend(t *testing.T) {
	ctx := context.Background()
	cfg := config.PersistenceConfig{Backend: "postgres"}

	_, err := repos.New(ctx, cfg)
	if err == nil {
		t.Fatal("expected error for unknown backend, got nil")
	}
}
