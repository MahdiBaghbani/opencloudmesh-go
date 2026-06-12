package wiring_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	tscfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/cfg"
	tslog "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/log"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
	wiringtest "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

const (
	expectedParityConcernCount   = 8
	expectedFixtureRegistryCount = 6
)

func TestEvidence_ParitySplitReplacesBootstrapMonolith(t *testing.T) {
	root := modroot.ModuleRoot(t)
	monolith := filepath.Join(root, wiringtest.MonolithParityTestRelPath)
	if _, err := os.Stat(monolith); err == nil {
		t.Fatalf("bootstrap parity monolith still present at %s; concerns must stay split under internal/wiring", wiringtest.MonolithParityTestRelPath)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat monolith path: %v", err)
	}

	if got := len(wiringtest.ParityConcernTestFiles); got != expectedParityConcernCount {
		t.Fatalf("ParityConcernTestFiles count = %d, want %d (concern-split registry incomplete)", got, expectedParityConcernCount)
	}

	wiringDir := wiringtest.WiringDir(root)
	for _, base := range wiringtest.ParityConcernTestFiles {
		path := filepath.Join(wiringDir, base)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("concern-split parity test missing %s: %v", base, err)
		}
	}
}

func TestEvidence_FixturesCentralizedInTestsupport(t *testing.T) {
	if got := len(wiringtest.FixtureRegistryIDs); got != expectedFixtureRegistryCount {
		t.Fatalf("FixtureRegistryIDs count = %d, want %d (fixture registry incomplete)", got, expectedFixtureRegistryCount)
	}

	for _, id := range wiringtest.FixtureRegistryIDs {
		switch id {
		case "HarnessWireOptions":
			if reflect.ValueOf(wiringtest.HarnessWireOptions).IsZero() {
				t.Fatal("HarnessWireOptions must not be zero")
			}
		case "ProductionWireOptions":
			// zero value is intentional for production path
		case "ExpectedCoreServicesOrder":
			if len(wiringtest.ExpectedCoreServicesOrder) == 0 {
				t.Fatal("ExpectedCoreServicesOrder must not be empty")
			}
		case "ExpectedAppServicesOrder":
			if len(wiringtest.ExpectedAppServicesOrder) == 0 {
				t.Fatal("ExpectedAppServicesOrder must not be empty")
			}
		case "ExpectedRootService":
			if wiringtest.ExpectedRootService == "" {
				t.Fatal("ExpectedRootService must not be empty")
			}
		case "ExpectedUnprotectedSets":
			if len(wiringtest.ExpectedUnprotectedSets) == 0 {
				t.Fatal("ExpectedUnprotectedSets must not be empty")
			}
		default:
			t.Fatalf("unknown fixture registry id %q", id)
		}
	}
}

func TestEvidence_WiringSkeletonScaffoldTypesPresent(t *testing.T) {
	var opts wiring.BuildOpts
	var result wiring.BuildResult
	if reflect.TypeOf(opts).Kind() != reflect.Struct {
		t.Fatalf("BuildOpts must be a struct type, got %v", reflect.TypeOf(opts))
	}
	if reflect.TypeOf(result).Kind() != reflect.Struct {
		t.Fatalf("BuildResult must be a struct type, got %v", reflect.TypeOf(result))
	}

	root := modroot.ModuleRoot(t)
	buildGo := filepath.Join(wiringtest.WiringDir(root), "build.go")
	body, err := os.ReadFile(buildGo)
	if err != nil {
		t.Fatalf("read build.go: %v", err)
	}
	text := string(body)
	for _, needle := range []string{
		"type BuildOpts struct",
		"type BuildResult struct",
		"func Build(",
	} {
		if !strings.Contains(text, needle) {
			// BuildOpts/BuildResult live in bootstrap.go when split from build.go.
			bootstrapGo, readErr := os.ReadFile(filepath.Join(wiringtest.WiringDir(root), "bootstrap.go"))
			if readErr != nil {
				t.Fatalf("read bootstrap.go: %v", readErr)
			}
			if !strings.Contains(string(bootstrapGo), needle) {
				t.Fatalf("wiring entrypoint missing marker %q", needle)
			}
		}
	}
}

func TestEvidence_BuildEntrypointReturnsExplicitDeps(t *testing.T) {
	cfg := tscfg.DevConfigHarness(18110)

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), harnessBuildOpts())
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if result.Deps == nil {
		t.Fatal("Build must return explicit Deps in BuildResult")
	}
	if result.RuntimeEval.DerivedTier == "" {
		t.Error("BuildResult.RuntimeEval.DerivedTier is empty")
	}
	if result.Persistence == nil {
		t.Error("BuildResult.Persistence is nil")
	}
}

func TestEvidence_BuildProductionZeroValueOpts(t *testing.T) {
	cfg := tscfg.DevConfigNoSignatures(18111)

	result, err := wiring.Build(cfg, tslog.DiscardLogger(), wiring.BuildOpts{})
	if err != nil {
		t.Fatalf("Build with zero opts failed: %v", err)
	}
	if result.Deps == nil {
		t.Fatal("Build must return explicit Deps in BuildResult")
	}
	if result.RuntimeEval.DerivedTier == "" {
		t.Error("BuildResult.RuntimeEval.DerivedTier is empty for production opts")
	}
	if result.Persistence == nil {
		t.Error("BuildResult.Persistence is nil")
	}
}

func TestEvidence_BuildSoleProductionImporterOfReposNew(t *testing.T) {
	root := modroot.ModuleRoot(t)
	const allowlistRel = "internal/wiring/build.go"
	assertAllowlistCallsFunction(t, root, allowlistRel, productionCallSpec{
		importSuffix: "/repos",
		funcName:     "New",
	})

	productionRoots := []string{"cmd", "internal", "tests/integration/harness"}
	violations := findProductionCallSites(t, root, productionRoots, allowlistRel, productionCallSpec{
		importSuffix: "/repos",
		funcName:     "New",
	}, true)
	if len(violations) > 0 {
		t.Fatalf("repos.New must only be called from %s; violations: %s",
			allowlistRel, strings.Join(violations, ", "))
	}
}

func TestEvidence_BuildUsesWireSharedDepsHook(t *testing.T) {
	root := modroot.ModuleRoot(t)
	buildGo, err := os.ReadFile(filepath.Join(wiringtest.WiringDir(root), "build.go"))
	if err != nil {
		t.Fatalf("read build.go: %v", err)
	}
	if !strings.Contains(string(buildGo), "wireSharedDepsHook(") {
		t.Fatal("build.go must call wireSharedDepsHook")
	}

	hooksGo, err := os.ReadFile(filepath.Join(wiringtest.WiringDir(root), "build_hooks.go"))
	if err != nil {
		t.Fatalf("read build_hooks.go: %v", err)
	}
	hooksText := string(hooksGo)
	if !strings.Contains(hooksText, "wireSharedDepsHook") || !strings.Contains(hooksText, "wireSharedDeps") {
		t.Fatal("build_hooks.go must wire wireSharedDepsHook to wireSharedDeps")
	}
}

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

func assertAllowlistCallsFunction(
	t *testing.T,
	root string,
	allowlistRel string,
	spec productionCallSpec,
) {
	t.Helper()
	if !allowlistReferencesFunction(t, root, allowlistRel, spec, true) {
		t.Fatalf("%s must call %s; wiring.Build owns the seam", allowlistRel, spec.funcName)
	}
}

func allowlistReferencesFunction(
	t *testing.T,
	root string,
	allowlistRel string,
	spec productionCallSpec,
	requireCall bool,
) bool {
	t.Helper()

	path := filepath.Join(root, allowlistRel)
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", allowlistRel, err)
	}

	imports := importNamesByPath(node)
	found := false
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
		if importSelectorMatches(imports, expr, spec) {
			found = true
			return false
		}
		return true
	})
	return found
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
