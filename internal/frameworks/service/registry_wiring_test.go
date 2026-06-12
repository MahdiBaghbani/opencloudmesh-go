package service_test

import (
	"slices"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
)

// TestCoreServiceNamesMatchesCoreServices guards parity between the wiring
// table and service.CoreServices. Lives in service_test to avoid an import
// cycle (wiring imports service).
func TestCoreServiceNamesMatchesCoreServices(t *testing.T) {
	if !slices.Equal(wiring.CoreServiceNames(), service.CoreServices) {
		t.Errorf(
			"wiring.CoreServiceNames() = %v, want service.CoreServices %v",
			wiring.CoreServiceNames(),
			service.CoreServices,
		)
	}
}
