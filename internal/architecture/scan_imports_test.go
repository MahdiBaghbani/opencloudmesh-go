// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package architecture

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func itoa(n int) string {
	return strconv.Itoa(n)
}

func findProductionImportSuffix(
	t *testing.T,
	root string,
	relRoots []string,
	importSuffix string,
) []string {
	t.Helper()

	return findProductionImports(t, root, relRoots, func(importPath string) bool {
		return strings.HasSuffix(importPath, importSuffix)
	})
}

func findProductionImportSegment(
	t *testing.T,
	root string,
	relRoots []string,
	segment string,
) []string {
	t.Helper()

	segment = strings.Trim(segment, "/")

	return findProductionImports(t, root, relRoots, func(importPath string) bool {
		return importPathHasSegment(importPath, segment)
	})
}

func findProductionImports(
	t *testing.T,
	root string,
	relRoots []string,
	match func(importPath string) bool,
) []string {
	t.Helper()

	var violations []string

	for _, relRoot := range relRoots {
		absRoot := filepath.Join(root, relRoot)
		if _, err := os.Stat(absRoot); os.IsNotExist(err) {
			t.Fatalf("production scan root missing: %s", relRoot)
		} else if err != nil {
			t.Fatalf("stat production scan root %s: %v", relRoot, err)
		}

		err := filepath.WalkDir(absRoot, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}

			if d.IsDir() {
				return nil
			}

			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			rel, err := filepath.Rel(root, path)
			if err != nil {
				return fmt.Errorf("architecture: scan imports: %w", err)
			}

			rel = filepath.ToSlash(rel)

			fset := token.NewFileSet()

			node, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", rel, err)
			}

			for _, imp := range node.Imports {
				importPath := strings.Trim(imp.Path.Value, `"`)
				if match(importPath) {
					pos := fset.Position(imp.Pos())
					violations = append(violations, rel+":"+strconv.Itoa(pos.Line))
				}
			}

			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", relRoot, err)
		}
	}

	return violations
}

func importPathHasSegment(importPath, segment string) bool {
	return slices.Contains(strings.Split(importPath, "/"), segment)
}
