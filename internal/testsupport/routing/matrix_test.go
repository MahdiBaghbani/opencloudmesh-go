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
}
