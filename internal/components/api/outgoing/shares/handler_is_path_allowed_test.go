// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsPathAllowed_RootPrefixAcceptsAbsolutePaths(t *testing.T) {
	t.Parallel()

	h := &Handler{allowedPaths: []string{string(os.PathSeparator)}}

	if !h.isPathAllowed(filepath.Join(string(os.PathSeparator), "etc", "passwd")) {
		t.Fatal("filesystem root prefix should allow absolute paths under it")
	}
}

func TestIsPathAllowed_SiblingPrefixRejected(t *testing.T) {
	t.Parallel()

	h := &Handler{allowedPaths: []string{"/tmp"}}

	if h.isPathAllowed("/tmp-evil/share.txt") {
		t.Fatal("sibling prefix /tmp-evil must not match allowed prefix /tmp")
	}
}
