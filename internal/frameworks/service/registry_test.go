package service

import (
	"slices"
	"testing"
)

// TestAppServicesMatchCoreServicesMinusRoot verifies the root service plus app
// services exactly reconstruct CoreServices in order. This prevents silent drift
// between service construction and route mounting when a core service is added,
// removed, or renamed.
func TestAppServicesMatchCoreServicesMinusRoot(t *testing.T) {
	if !slices.Contains(CoreServices, RootService) {
		t.Fatalf("RootService %q is not present in CoreServices %v", RootService, CoreServices)
	}

	app := AppServices()

	if slices.Contains(app, RootService) {
		t.Errorf("AppServices() must not include RootService %q, got %v", RootService, app)
	}

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

	if len(app)+1 != len(CoreServices) {
		t.Errorf("AppServices() length %d + 1 root != CoreServices length %d", len(app), len(CoreServices))
	}
}

// TestDescriptorsDerivedViews verifies CoreServices stay aligned with the
// canonical descriptor table.
func TestDescriptorsDerivedViews(t *testing.T) {
	descs := Descriptors()
	if len(descs) != len(CoreServices) {
		t.Fatalf("descriptor count = %d, want CoreServices length %d", len(descs), len(CoreServices))
	}

	names := make([]string, len(descs))
	rootCount := 0
	for i, d := range descs {
		names[i] = d.Name
		if d.Build == "" {
			t.Errorf("descriptor %q has no build key", d.Name)
		}
		if d.MountAtRoot {
			rootCount++
			if d.Name != RootService {
				t.Errorf("MountAtRoot service = %q, want RootService %q", d.Name, RootService)
			}
		}
		if d.Prefix != "" && d.MountAtRoot {
			t.Errorf("descriptor %q is MountAtRoot but has prefix %q", d.Name, d.Prefix)
		}
	}
	if !slices.Equal(names, CoreServices) {
		t.Errorf("descriptor names = %v, want CoreServices %v", names, CoreServices)
	}
	if rootCount != 1 {
		t.Fatalf("MountAtRoot descriptor count = %d, want 1", rootCount)
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
