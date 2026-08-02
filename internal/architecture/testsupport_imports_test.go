// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package architecture

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

const testsupportImportPrefix = "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport"

func TestTestsupportOnlyImportedFromTestFiles(t *testing.T) {
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

		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		relPath = filepath.ToSlash(relPath)

		if strings.HasPrefix(relPath, "internal/testsupport/") {
			return nil
		}

		if strings.HasSuffix(relPath, "_test.go") {
			return nil
		}

		imports, err := parseGoImports(path)
		if err != nil {
			return err
		}

		for _, imp := range imports {
			if strings.HasPrefix(imp, testsupportImportPrefix) {
				violations = append(violations, relPath+": imports testsupport from non-test file: "+imp)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	if len(violations) > 0 {
		t.Fatalf("internal/testsupport must only be imported from _test.go outside testsupport tree:\n%s",
			strings.Join(violations, "\n"))
	}
}

func parseGoImports(path string) ([]string, error) {
	fset := token.NewFileSet()

	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}

	imports := make([]string, 0, len(f.Imports))
	for _, spec := range f.Imports {
		imports = append(imports, strings.Trim(spec.Path.Value, `"`))
	}

	return imports, nil
}
