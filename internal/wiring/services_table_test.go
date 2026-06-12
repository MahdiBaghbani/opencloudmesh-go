package wiring_test

import (
	"slices"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
)

func TestCoreServiceTableMatchesCoreServices(t *testing.T) {
	tableNames := wiring.CoreServiceNames()
	if !slices.Equal(tableNames, service.CoreServices) {
		t.Fatalf("CoreServiceNames() = %v, want service.CoreServices %v",
			tableNames, service.CoreServices)
	}
}
