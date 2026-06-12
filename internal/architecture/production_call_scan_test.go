package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type productionCallSpec struct {
	importSuffix string
	funcName     string
}

func findProductionCallSites(
	t *testing.T,
	root string,
	relRoots []string,
	allowlistRel string,
	spec productionCallSpec,
	requireCall bool,
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
			if rel == allowlistRel {
				return nil
			}

			fset := token.NewFileSet()
			node, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", rel, err)
			}

			imports := importNamesByPath(node)
			ast.Inspect(node, func(n ast.Node) bool {
				var expr ast.Expr
				if requireCall {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					expr = call.Fun
				} else {
					sel, ok := n.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					expr = sel
				}
				if !importSelectorMatches(imports, expr, spec) {
					return true
				}
				pos := fset.Position(expr.Pos())
				violations = append(violations, rel+":"+strconv.Itoa(pos.Line))
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", relRoot, err)
		}
	}
	return violations
}

func importNamesByPath(f *ast.File) map[string]string {
	names := make(map[string]string)
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		name := filepath.Base(path)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		names[name] = path
	}
	return names
}

func importSelectorMatches(
	imports map[string]string,
	expr ast.Expr,
	spec productionCallSpec,
) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != spec.funcName {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	importPath, ok := imports[pkg.Name]
	return ok && strings.HasSuffix(importPath, spec.importSuffix)
}

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
