package architecture

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func findProductionImportSuffix(
	t *testing.T,
	root string,
	relRoots []string,
	importSuffix string,
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
				return err
			}
			rel = filepath.ToSlash(rel)

			fset := token.NewFileSet()
			node, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", rel, err)
			}
			for _, imp := range node.Imports {
				importPath := strings.Trim(imp.Path.Value, `"`)
				if strings.HasSuffix(importPath, importSuffix) {
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
