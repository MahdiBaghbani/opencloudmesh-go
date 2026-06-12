package service

import (
	"slices"
	"testing"

	wiringtest "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/wiring"
)

func TestRegistryContract_CoreServicesOrder(t *testing.T) {
	if !slices.Equal(CoreServices, wiringtest.ExpectedCoreServicesOrder) {
		t.Fatalf("CoreServices = %v, want %v", CoreServices, wiringtest.ExpectedCoreServicesOrder)
	}
}

func TestRegistryContract_RootService(t *testing.T) {
	if RootService != wiringtest.ExpectedRootService {
		t.Fatalf("RootService = %q, want %q", RootService, wiringtest.ExpectedRootService)
	}
}

func TestRegistryContract_AppServicesOrder(t *testing.T) {
	got := AppServices()
	if !slices.Equal(got, wiringtest.ExpectedAppServicesOrder) {
		t.Fatalf("AppServices() = %v, want %v", got, wiringtest.ExpectedAppServicesOrder)
	}
}

func TestRegistryContract_AppServicesDerivedFromCoreServices(t *testing.T) {
	want := make([]string, 0, len(CoreServices))
	for _, name := range CoreServices {
		if name == RootService {
			continue
		}
		want = append(want, name)
	}
	if !slices.Equal(AppServices(), want) {
		t.Fatalf("AppServices() = %v, want derived %v", AppServices(), want)
	}
}
