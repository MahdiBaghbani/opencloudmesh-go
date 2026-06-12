package wiring_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring/wiringtest"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

const (
	tddExpectedParityConcernCount = 8
	tddExpectedT0FixtureCount     = 6
)

func TestTDD_ParitySplitReplacesBootstrapMonolith(t *testing.T) {
	root := wiringtest.ModuleRoot(t)
	monolith := filepath.Join(root, wiringtest.MonolithParityTestRelPath)
	if _, err := os.Stat(monolith); err == nil {
		t.Fatalf("bootstrap parity monolith still present at %s; T1 must split concerns under internal/wiring", wiringtest.MonolithParityTestRelPath)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat monolith path: %v", err)
	}

	if got := len(wiringtest.ParityConcernTestFiles); got != tddExpectedParityConcernCount {
		t.Fatalf("ParityConcernTestFiles count = %d, want %d (concern-split registry incomplete)", got, tddExpectedParityConcernCount)
	}

	wiringDir := wiringtest.WiringDir(root)
	for _, base := range wiringtest.ParityConcernTestFiles {
		path := filepath.Join(wiringDir, base)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("concern-split parity test missing %s: %v", base, err)
		}
	}
}

func TestTDD_T0SnapshotFixturesCentralizedInWiringtest(t *testing.T) {
	if got := len(wiringtest.T0SnapshotFixtureIDs); got != tddExpectedT0FixtureCount {
		t.Fatalf("T0SnapshotFixtureIDs count = %d, want %d (T0 fixture registry incomplete)", got, tddExpectedT0FixtureCount)
	}

	for _, id := range wiringtest.T0SnapshotFixtureIDs {
		switch id {
		case "SnapshotHarnessWireOptions":
			if reflect.ValueOf(wiringtest.SnapshotHarnessWireOptions).IsZero() {
				t.Fatal("SnapshotHarnessWireOptions must not be zero")
			}
		case "SnapshotProductionWireOptions":
			// zero value is intentional for production path
		case "SnapshotCoreServicesOrder":
			if len(wiringtest.SnapshotCoreServicesOrder) == 0 {
				t.Fatal("SnapshotCoreServicesOrder must not be empty")
			}
		case "SnapshotAppServicesOrder":
			if len(wiringtest.SnapshotAppServicesOrder) == 0 {
				t.Fatal("SnapshotAppServicesOrder must not be empty")
			}
		case "SnapshotRootService":
			if wiringtest.SnapshotRootService == "" {
				t.Fatal("SnapshotRootService must not be empty")
			}
		case "SnapshotUnprotectedSets":
			if len(wiringtest.SnapshotUnprotectedSets) == 0 {
				t.Fatal("SnapshotUnprotectedSets must not be empty")
			}
		default:
			t.Fatalf("unknown T0 snapshot fixture id %q", id)
		}
	}
}

func TestTDD_WiringSkeletonScaffoldTypesPresent(t *testing.T) {
	var opts wiring.BuildOpts
	var result wiring.BuildResult
	if reflect.TypeOf(opts).Kind() != reflect.Struct {
		t.Fatalf("BuildOpts must be a struct type, got %v", reflect.TypeOf(opts))
	}
	if reflect.TypeOf(result).Kind() != reflect.Struct {
		t.Fatalf("BuildResult must be a struct type, got %v", reflect.TypeOf(result))
	}

	root := wiringtest.ModuleRoot(t)
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
			// BuildOpts/BuildResult live in bootstrap.go after T6; accept either file.
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

func TestTDD_BuildEntrypointReturnsExplicitDeps(t *testing.T) {
	cfg := wiringtest.DevConfigHarness(18110)

	result, err := wiring.Build(cfg, wiringtest.DiscardLogger(), harnessBuildOpts())
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

func TestTDD_BuildProductionZeroValueOpts(t *testing.T) {
	cfg := wiringtest.DevConfigNoSignatures(18111)

	result, err := wiring.Build(cfg, wiringtest.DiscardLogger(), wiring.BuildOpts{})
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

func TestTDD_BuildSoleProductionImporterOfReposNew(t *testing.T) {
	root := wiringtest.ModuleRoot(t)
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

func TestTDD_BuildUsesWireSharedDepsHook(t *testing.T) {
	root := wiringtest.ModuleRoot(t)
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
