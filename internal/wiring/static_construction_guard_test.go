package wiring_test

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
	"strings"
	"testing"
)

func TestTDD_NoProductionDynamicServiceConstruction(t *testing.T) {
	root := modroot.ModuleRoot(t)
	productionRoots := []string{"cmd", "internal", "tests/integration/harness"}
	violations := findProductionCallSites(t, root, productionRoots, "", productionCallSpec{
		importSuffix: "/service",
		funcName:     "Get",
	}, true)
	if len(violations) > 0 {
		t.Fatalf("service.Get must not appear in production code; violations: %s",
			strings.Join(violations, ", "))
	}
}

func TestTDD_NoProductionDynamicInterceptorConstruction(t *testing.T) {
	root := modroot.ModuleRoot(t)
	productionRoots := []string{"cmd", "internal", "tests/integration/harness"}
	violations := findProductionCallSites(t, root, productionRoots, "", productionCallSpec{
		importSuffix: "/interceptors",
		funcName:     "Get",
	}, true)
	if len(violations) > 0 {
		t.Fatalf("interceptors.Get must not appear in production code; violations: %s",
			strings.Join(violations, ", "))
	}
}

func TestTDD_NoProductionServiceLoaderImports(t *testing.T) {
	root := modroot.ModuleRoot(t)
	productionRoots := []string{"cmd", "internal", "tests/integration/harness"}
	violations := findProductionImportSuffix(t, root, productionRoots, "/services/loader")
	if len(violations) > 0 {
		t.Fatalf("services/loader blank imports must not appear in production code; violations: %s",
			strings.Join(violations, ", "))
	}
}

func TestTDD_NoProductionInterceptorLoaderImports(t *testing.T) {
	root := modroot.ModuleRoot(t)
	productionRoots := []string{"cmd", "internal", "tests/integration/harness"}
	violations := findProductionImportSuffix(t, root, productionRoots, "/interceptors/loader")
	if len(violations) > 0 {
		t.Fatalf("interceptors/loader blank imports must not appear in production code; violations: %s",
			strings.Join(violations, ", "))
	}
}
