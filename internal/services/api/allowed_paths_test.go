// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package api

import (
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestResolveOutgoingAllowedPaths_DefaultsToContentRoot(t *testing.T) { //nolint:paralleltest // uses t.Chdir
	t.Chdir(t.TempDir())

	contentDir := ".ocm/files"

	got, err := resolveOutgoingAllowedPaths(contentDir, nil)
	if err != nil {
		t.Fatalf("resolveOutgoingAllowedPaths: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected one allowed path, got %v", got)
	}

	cwd, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("Abs cwd: %v", err)
	}

	want := filepath.Join(cwd, contentDir)
	if got[0] != want {
		t.Fatalf("allowed path = %q, want %q", got[0], want)
	}
}

func TestResolveOutgoingAllowedPaths_ExplicitConfigWins(t *testing.T) {
	t.Parallel()

	configured := []string{"/custom/share-root"}

	got, err := resolveOutgoingAllowedPaths("", configured)
	if err != nil {
		t.Fatalf("resolveOutgoingAllowedPaths: %v", err)
	}

	if len(got) != 1 || got[0] != configured[0] {
		t.Fatalf("allowed paths = %v, want %v", got, configured)
	}
}

func TestResolveOutgoingAllowedPaths_MatchesAPIWiringDefault(t *testing.T) { //nolint:paralleltest // uses t.Chdir
	t.Chdir(t.TempDir())

	contentDir := config.DefaultContentDir

	got, err := resolveOutgoingAllowedPaths(contentDir, nil)
	if err != nil {
		t.Fatalf("resolveOutgoingAllowedPaths: %v", err)
	}

	root, err := config.ResolveContentDir(contentDir)
	if err != nil {
		t.Fatalf("ResolveContentDir: %v", err)
	}

	if len(got) != 1 || got[0] != root {
		t.Fatalf("allowed paths = %v, want [%q]", got, root)
	}
}
