package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestSlogKeysAreSnakeCase scans Go source files for slog calls and verifies
// that all attribute keys are snake_case.
//
// This is an AST-based enforcement test per the plan:
// "Unit tests: enforce snake_case structured log keys (no clientId, shareId, expiresIn;
// keyId is allowed as RFC 9421 term)"
func TestSlogKeysAreSnakeCase(t *testing.T) {
	// Packages to scan (relative to repo root)
	packagesToScan := []string{
		"internal/ocm",
		"internal/webdav",
		"internal/crypto",
		"internal/federation",
		"internal/identity",
		"internal/server",
	}

	// Allowed exceptions (RFC terms, etc.)
	allowedExceptions := map[string]bool{
		"keyId": true, // RFC 9421 term
	}

	// Regex for snake_case: lowercase letters, numbers, underscores only
	snakeCaseRegex := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

	// Find repo root
	repoRoot := findRepoRoot(t)

	var violations []string

	for _, pkg := range packagesToScan {
		pkgPath := filepath.Join(repoRoot, pkg)
		if _, err := os.Stat(pkgPath); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(pkgPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Skip test files and non-Go files
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			// Parse the file
			fset := token.NewFileSet()
			node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				// Skip files that don't parse (might be generated or have syntax issues)
				return nil
			}

			// Find slog calls and check keys
			ast.Inspect(node, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}

				// Check if this is a slog method call (Debug, Info, Warn, Error, With)
				if !isSlogCall(call) {
					return true
				}

				// Extract and check string literal keys from the call
				keys := extractSlogKeys(call)
				for _, key := range keys {
					if allowedExceptions[key] {
						continue
					}
					if !snakeCaseRegex.MatchString(key) {
						relPath, _ := filepath.Rel(repoRoot, path)
						pos := fset.Position(call.Pos())
						violations = append(violations, 
							relPath+":"+itoa(pos.Line)+": slog key \""+key+"\" is not snake_case")
					}
				}

				return true
			})

			return nil
		})
		if err != nil {
			t.Fatalf("failed to walk %s: %v", pkgPath, err)
		}
	}

	if len(violations) > 0 {
		t.Errorf("Found %d slog keys that are not snake_case:\n%s", 
			len(violations), strings.Join(violations, "\n"))
	}
}

// isSlogCall checks if this is a call to slog methods that accept key-value pairs.
func isSlogCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	// Check method name
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

	// Try to identify if this is on a *slog.Logger or appctx.GetLogger result
	// We'll be permissive and check any call matching these method names
	// on an identifier that looks like a logger (contains "log" or "logger")
	switch x := sel.X.(type) {
	case *ast.Ident:
		name := strings.ToLower(x.Name)
		if strings.Contains(name, "log") || name == "l" || name == "h" {
			return true
		}
	case *ast.SelectorExpr:
		// e.g., h.logger.Info or s.logger.Debug
		name := strings.ToLower(x.Sel.Name)
		if strings.Contains(name, "log") {
			return true
		}
	case *ast.CallExpr:
		// e.g., appctx.GetLogger(ctx).Info
		if sel2, ok := x.Fun.(*ast.SelectorExpr); ok {
			if sel2.Sel.Name == "GetLogger" {
				return true
			}
		}
	}

	return false
}

// extractSlogKeys extracts string literal keys from a slog call.
// slog calls have format: logger.Info("message", "key1", val1, "key2", val2, ...)
// The first arg is the message, then key-value pairs follow.
func extractSlogKeys(call *ast.CallExpr) []string {
	var keys []string

	// Skip first arg (message) if it exists
	if len(call.Args) < 2 {
		return keys
	}

	// Process remaining args as key-value pairs
	for i := 1; i < len(call.Args); i += 2 {
		arg := call.Args[i]

		// Only check string literals (skip variable references, slog.Attr, etc.)
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}

		// Remove quotes from string literal
		key := strings.Trim(lit.Value, "\"'`")
		if key != "" {
			keys = append(keys, key)
		}
	}

	return keys
}

// findRepoRoot finds the repository root by looking for go.mod
func findRepoRoot(t *testing.T) string {
	// Start from current directory and walk up
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod in any parent directory")
		}
		dir = parent
	}
}

// itoa converts int to string without importing strconv
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
