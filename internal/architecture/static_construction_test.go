package architecture

import (
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

func TestNoProductionDynamicServiceConstruction(t *testing.T) {
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

func TestNoProductionDynamicInterceptorConstruction(t *testing.T) {
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
