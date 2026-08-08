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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

func TestSlogKeysAreSnakeCase(t *testing.T) {
	t.Parallel()

	packagesToScan := []string{
		"internal/services/ocm",
		"internal/components/webdav",
		"internal/platform/crypto",
		"internal/components/ocmaux",
		"internal/components/ocm/peertrust",
		"internal/components/ocm/directoryservice",
		"internal/components/ocm/shares/incoming",
		"internal/components/ocm/invites/outgoing/accepted",
		"internal/components/ocm/token/incoming",
		"internal/components/identity",
		"internal/platform/http/server",
		"internal/platform/http/middleware",
		"internal/components/identity/sessiongate",
		"internal/components/ocm/inbound/signature",
		"internal/platform/http/tls",
		"internal/platform/http/client",
	}

	allowedExceptions := map[string]bool{
		"keyId": true,
	}

	snakeCaseRegex := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	root := modroot.ModuleRoot(t)

	var violations []string

	for _, pkg := range packagesToScan {
		pkgViolations, err := scanPackageSlogKeys(root, pkg, snakeCaseRegex, allowedExceptions)
		if err != nil {
			t.Fatalf("failed to walk %s: %v", filepath.Join(root, pkg), err)
		}

		violations = append(violations, pkgViolations...)
	}

	if len(violations) > 0 {
		t.Errorf("Found %d slog keys that are not snake_case:\n%s",
			len(violations), strings.Join(violations, "\n"))
	}
}

// scanPackageSlogKeys walks one package tree and collects non-snake_case slog
// keys from its Go sources.
func scanPackageSlogKeys(root, pkg string, snakeCaseRegex *regexp.Regexp, allowedExceptions map[string]bool) ([]string, error) {
	pkgPath := filepath.Join(root, pkg)
	if _, err := os.Stat(pkgPath); os.IsNotExist(err) {
		return nil, nil
	}

	var violations []string

	err := filepath.Walk(pkgPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		fileViolations, err := scanFileSlogKeys(root, path, snakeCaseRegex, allowedExceptions)
		if err != nil {
			return err
		}

		violations = append(violations, fileViolations...)

		return nil
	})
	if err != nil {
		return violations, fmt.Errorf("architecture: scan slog keys: %w", err)
	}

	return violations, nil
}

// scanFileSlogKeys parses one Go file and collects its non-snake_case slog keys.
func scanFileSlogKeys(root, path string, snakeCaseRegex *regexp.Regexp, allowedExceptions map[string]bool) ([]string, error) {
	fset := token.NewFileSet()

	node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, nil //nolint:nilerr // test: unparseable files are skipped, not treated as walk errors
	}

	relPath, err := filepath.Rel(root, path)
	if err != nil {
		return nil, fmt.Errorf("architecture: scan slog keys: %w", err)
	}

	var violations []string

	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isSlogCall(call) {
			return true
		}

		violations = append(violations, slogKeyViolations(fset, call, relPath, snakeCaseRegex, allowedExceptions)...)

		return true
	})

	return violations, nil
}

// slogKeyViolations checks the keys of one slog call against the snake_case rule.
func slogKeyViolations(fset *token.FileSet, call *ast.CallExpr, relPath string, snakeCaseRegex *regexp.Regexp, allowedExceptions map[string]bool) []string {
	var violations []string

	for _, key := range extractSlogKeys(call) {
		if allowedExceptions[key] || snakeCaseRegex.MatchString(key) {
			continue
		}

		pos := fset.Position(call.Pos())
		violations = append(violations,
			relPath+":"+itoa(pos.Line)+": slog key \""+key+"\" is not snake_case")
	}

	return violations
}

func isSlogCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	method := sel.Sel.Name
	slogMethods := map[string]bool{
		"Debug": true,
		"Info":  true,
		"Warn":  true,
		"Error": true,
		"With":  true,
	}

	if !slogMethods[method] {
		return false
	}

	switch x := sel.X.(type) {
	case *ast.Ident:
		name := strings.ToLower(x.Name)
		if strings.Contains(name, "log") || name == "l" || name == "h" {
			return true
		}
	case *ast.SelectorExpr:
		name := strings.ToLower(x.Sel.Name)
		if strings.Contains(name, "log") {
			return true
		}
	case *ast.CallExpr:
		if sel2, ok := x.Fun.(*ast.SelectorExpr); ok {
			if sel2.Sel.Name == "GetLogger" {
				return true
			}
		}
	}

	return false
}

func extractSlogKeys(call *ast.CallExpr) []string {
	var keys []string

	if len(call.Args) < 2 {
		return keys
	}

	for i := 1; i < len(call.Args); i += 2 {
		arg := call.Args[i]

		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}

		key := strings.Trim(lit.Value, "\"'`")
		if key != "" {
			keys = append(keys, key)
		}
	}

	return keys
}
