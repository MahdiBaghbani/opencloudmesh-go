// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package architecture

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

func TestNoDirectForwardedHeaderParsing(t *testing.T) {
	t.Parallel()

	forbidden := []string{"X-Forwarded-For", "X-Real-IP"}

	allowedSubstrings := []string{
		"/platform/http/realip/",
		"/architecture/",
	}

	root := modroot.ModuleRoot(t)

	var violations []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}

			return nil
		}

		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		p := filepath.ToSlash(path)
		for _, allow := range allowedSubstrings {
			if strings.Contains(p, allow) {
				return nil
			}
		}

		data, err := os.ReadFile(path) //nolint:gosec // architecture test: read-only repo walk, no symlink TOCTOU risk
		if err != nil {
			return fmt.Errorf("architecture: check forwarded header: %w", err)
		}

		content := string(data)
		for _, token := range forbidden {
			if strings.Contains(content, token) {
				violations = append(violations, p)

				break
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	if len(violations) > 0 {
		t.Fatalf("Found X-Forwarded-For/X-Real-IP references outside realip (see allowlist rules in this test):\n%s",
			strings.Join(violations, "\n"))
	}
}
