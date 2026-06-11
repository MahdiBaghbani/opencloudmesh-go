package wiring_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring/wiringtest"
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
	if reflect.TypeOf(opts).Name() == "" && reflect.TypeOf(opts).Kind() != reflect.Struct {
		t.Fatalf("BuildOpts must alias a named struct type, got %v", reflect.TypeOf(opts))
	}
	if reflect.TypeOf(result).Name() == "" && reflect.TypeOf(result).Kind() != reflect.Struct {
		t.Fatalf("BuildResult must alias a named struct type, got %v", reflect.TypeOf(result))
	}

	root := wiringtest.ModuleRoot(t)
	buildGo := filepath.Join(wiringtest.WiringDir(root), "build.go")
	body, err := os.ReadFile(buildGo)
	if err != nil {
		t.Fatalf("read build.go: %v", err)
	}
	text := string(body)
	for _, needle := range []string{
		"type BuildOpts =",
		"type BuildResult =",
		"T1 skeleton",
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("build.go missing T1 scaffold marker %q", needle)
		}
	}
}
