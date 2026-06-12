package service

import (
	"slices"
	"testing"

	wiringtest "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/wiring"
)

// TestAppServicesParity guards the core-service parity contract: the root
// service plus the app services must exactly reconstruct CoreServices, in
// order. This prevents silent drift between service construction and route
// mounting when a core service is added, removed, or renamed.
func TestAppServicesParity(t *testing.T) {
	// RootService must be a member of CoreServices.
	if !slices.Contains(CoreServices, RootService) {
		t.Fatalf("RootService %q is not present in CoreServices %v", RootService, CoreServices)
	}

	app := AppServices()

	// AppServices must never include the root service.
	if slices.Contains(app, RootService) {
		t.Errorf("AppServices() must not include RootService %q, got %v", RootService, app)
	}

	// Reconstructing CoreServices from RootService + AppServices, preserving
	// CoreServices order, must match exactly (no dropped or extra services).
	want := make([]string, 0, len(CoreServices))
	for _, name := range CoreServices {
		if name == RootService {
			continue
		}
		want = append(want, name)
	}
	if !slices.Equal(app, want) {
		t.Errorf("AppServices() = %v, want %v (CoreServices order minus RootService)", app, want)
	}

	// Every core service must be accounted for: root or app, no overlap.
	if len(app)+1 != len(CoreServices) {
		t.Errorf("AppServices() length %d + 1 root != CoreServices length %d", len(app), len(CoreServices))
	}
}

// TestServiceOrderMatchesWiringFixtures guards the static CoreServices table
// against the shared wiring fixture baseline used by bootstrap parity tests.
func TestServiceOrderMatchesWiringFixtures(t *testing.T) {
	if !slices.Equal(CoreServices, wiringtest.ExpectedCoreServicesOrder) {
		t.Errorf(
			"CoreServices = %v, want %v",
			CoreServices,
			wiringtest.ExpectedCoreServicesOrder,
		)
	}
	if RootService != wiringtest.ExpectedRootService {
		t.Errorf(
			"RootService = %q, want %q",
			RootService,
			wiringtest.ExpectedRootService,
		)
	}
	if !slices.Equal(AppServices(), wiringtest.ExpectedAppServicesOrder) {
		t.Errorf(
			"AppServices() = %v, want %v",
			AppServices(),
			wiringtest.ExpectedAppServicesOrder,
		)
	}
}

func TestCheckServiceNames(t *testing.T) {
	t.Run("all valid", func(t *testing.T) {
		unknown, allowed := CheckServiceNames(CoreServices)
		if unknown != nil {
			t.Fatalf("unknown = %v, want nil", unknown)
		}
		if allowed != nil {
			t.Fatalf("allowed = %v, want nil", allowed)
		}
	})

	t.Run("unknown names rejected", func(t *testing.T) {
		names := []string{"ocm", "bogus", "api", "also-bad"}
		unknown, allowed := CheckServiceNames(names)
		if !slices.Equal(unknown, []string{"also-bad", "bogus"}) {
			t.Fatalf("unknown = %v, want sorted [also-bad bogus]", unknown)
		}
		if !slices.Equal(allowed, CoreServices) {
			t.Fatalf("allowed = %v, want CoreServices %v", allowed, CoreServices)
		}
	})
}
