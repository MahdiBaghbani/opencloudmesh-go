package architecture

import (
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
	packagesToScan := []string{
		"internal/services/ocm",
		"internal/components/webdav",
		"internal/platform/crypto",
		"internal/components/ocmaux",
		"internal/components/ocm/peertrust",
		"internal/components/ocm/directoryservice",
		"internal/components/ocm/peercompat",
		"internal/components/ocm/outboundsigning",
		"internal/components/ocm/shares/incoming",
		"internal/components/ocm/invites/incoming",
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
		pkgPath := filepath.Join(root, pkg)
		if _, err := os.Stat(pkgPath); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(pkgPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			fset := token.NewFileSet()
			node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return nil
			}

			ast.Inspect(node, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}

				if !isSlogCall(call) {
					return true
				}

				keys := extractSlogKeys(call)
				for _, key := range keys {
					if allowedExceptions[key] {
						continue
					}
					if !snakeCaseRegex.MatchString(key) {
						relPath, _ := filepath.Rel(root, path)
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
