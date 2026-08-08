// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package architecture

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

var (
	rawProviderFieldNames = map[string]bool{
		"SenderFQDN":           true,
		"AcceptedProviderFQDN": true,
		"ProviderFQDN":         true,
	}
	planBreadcrumbInString = regexp.MustCompile(`(?:^|[^a-zA-Z0-9_])(?:Phase\s+)?[FTQPW]\d+(?:\.[0-9]+)?(?:[^a-zA-Z0-9_]|$)`)
)

func TestFindAccepted_NoRawFallback(t *testing.T) {
	t.Parallel()
	root := modroot.ModuleRoot(t)

	violations, found, err := scanFindAcceptedBodies(root)
	if err != nil {
		t.Fatalf("scan FindAccepted bodies: %v", err)
	}

	if found == 0 {
		t.Fatal("expected at least one FindAccepted implementation to guard")
	}

	if len(violations) > 0 {
		t.Fatalf("FindAccepted raw-fallback or planning-metadata violations:\n%s",
			strings.Join(violations, "\n"))
	}
}

// scanFindAcceptedBodies walks production Go sources and AST-scans FindAccepted
// function bodies for raw provider lookups and planning breadcrumbs.
func scanFindAcceptedBodies(root string) (violations []string, found int, err error) {
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if d.IsDir() {
			return skipHeavyDir(d)
		}

		fileViolations, fileFound, scanErr := scanFileFindAcceptedBodies(root, path)
		if scanErr != nil {
			return scanErr
		}

		found += fileFound

		violations = append(violations, fileViolations...)

		return nil
	})
	if err != nil {
		return violations, found, fmt.Errorf("architecture: check findaccepted guard: %w", err)
	}

	return violations, found, nil
}

// scanFileFindAcceptedBodies parses one Go file and inspects FindAccepted bodies.
func scanFileFindAcceptedBodies(root, path string) ([]string, int, error) {
	if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
		return nil, 0, nil
	}

	rel, err := filepath.Rel(root, path)
	if err != nil {
		return nil, 0, fmt.Errorf("architecture: check findaccepted guard: %w", err)
	}

	rel = filepath.ToSlash(rel)

	fset := token.NewFileSet()

	node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, 0, nil //nolint:nilerr // test: unparseable files are skipped, not walk errors
	}

	var violations []string

	found := 0
	imports := fileImportLocalNames(node)

	for _, decl := range node.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !strings.Contains(fn.Name.Name, "FindAccepted") {
			continue
		}

		found++

		bodyViolations := findAcceptedBodyViolations(fset, fn, rel, imports)
		violations = append(violations, bodyViolations...)
	}

	return violations, found, nil
}

// fileImportLocalNames maps each import's local name (alias, explicit name, or
// default last path element) to its import path. Dot imports use ".".
func fileImportLocalNames(file *ast.File) map[string]string {
	out := make(map[string]string, len(file.Imports))

	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		local := filepath.Base(path)

		if imp.Name != nil {
			local = imp.Name.Name
		}

		out[local] = path
	}

	return out
}

// findAcceptedBodyViolations AST-walks one FindAccepted function body.
func findAcceptedBodyViolations(
	fset *token.FileSet,
	fn *ast.FuncDecl,
	relPath string,
	imports map[string]string,
) []string {
	var violations []string

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if rawProviderFieldNames[x.Sel.Name] {
				pos := fset.Position(x.Sel.Pos())
				violations = append(violations,
					relPath+":"+itoa(pos.Line)+": FindAccepted "+fn.Name.Name+
						" uses raw provider field "+x.Sel.Name)
			}
		case *ast.KeyValueExpr:
			// Struct-literal field keys are Ident nodes, not SelectorExpr.
			if key, ok := x.Key.(*ast.Ident); ok && rawProviderFieldNames[key.Name] {
				pos := fset.Position(key.Pos())
				violations = append(violations,
					relPath+":"+itoa(pos.Line)+": FindAccepted "+fn.Name.Name+
						" uses raw provider field "+key.Name+" in struct literal")
			}
		case *ast.CallExpr:
			if kind, ok := rawNormalizationCallKind(x, imports); ok {
				pos := fset.Position(x.Pos())
				violations = append(violations,
					relPath+":"+itoa(pos.Line)+": FindAccepted "+fn.Name.Name+
						" uses "+kind+" (raw normalization fallback)")
			}
		case *ast.BasicLit:
			if x.Kind != token.STRING {
				return true
			}

			lit := strings.Trim(x.Value, `"`)
			if planBreadcrumbInString.MatchString(lit) {
				pos := fset.Position(x.Pos())
				violations = append(violations,
					relPath+":"+itoa(pos.Line)+": FindAccepted "+fn.Name.Name+
						" contains planning-metadata breadcrumb in string literal")
			}
		}

		return true
	})

	return violations
}

// rawNormalizationCallKind reports whether call is an inline raw normalization
// fallback (strings case-folding or hostport.Normalize), including aliased and
// dot-imported forms.
func rawNormalizationCallKind(call *ast.CallExpr, imports map[string]string) (string, bool) {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		ident, ok := fun.X.(*ast.Ident)
		if !ok {
			return "", false
		}

		return normalizationKindFor(imports[ident.Name], fun.Sel.Name)
	case *ast.Ident:
		// Dot-import call sites: ToLower(x), EqualFold(a, b), Normalize(a, b).
		return normalizationKindFor(imports["."], fun.Name)
	default:
		return "", false
	}
}

func normalizationKindFor(impPath, funcName string) (string, bool) {
	if impPath == "" {
		return "", false
	}

	if isStringsImportPath(impPath) && (funcName == "ToLower" || funcName == "EqualFold") {
		return "strings." + funcName, true
	}

	if isHostportImportPath(impPath) && funcName == "Normalize" {
		return "hostport.Normalize", true
	}

	return "", false
}

func isStringsImportPath(path string) bool {
	return path == "strings"
}

func isHostportImportPath(path string) bool {
	return path == "hostport" || strings.HasSuffix(path, "/hostport")
}
