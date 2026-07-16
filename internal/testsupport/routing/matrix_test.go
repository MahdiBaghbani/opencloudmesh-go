package routing

import (
	"slices"
	"testing"
)

func TestHostRootDiscoveryPaths_CanonicalOnly(t *testing.T) {
	paths := HostRootDiscoveryPaths()
	want := []string{"/.well-known/ocm"}
	if !slices.Equal(paths, want) {
		t.Fatalf("HostRootDiscoveryPaths() = %v, want %v", paths, want)
	}
	for _, path := range paths {
		if path == "/ocm-provider" || path == "/ocm-provider/" {
			t.Fatalf("legacy discovery path %q must not appear in HostRootDiscoveryPaths", path)
		}
	}
}
