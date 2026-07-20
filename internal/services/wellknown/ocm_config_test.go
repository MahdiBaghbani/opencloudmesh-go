package wellknown

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
)

func TestProviderConfig_ApplyDefaults(t *testing.T) {
	c := &resolve.ProviderConfig{}
	c.ApplyDefaults()

	if c.Provider != "OpenCloudMesh" {
		t.Errorf("expected Provider 'OpenCloudMesh', got %q", c.Provider)
	}
}

func TestProviderConfig_ApplyDefaults_PreservesCustomValues(t *testing.T) {
	c := &resolve.ProviderConfig{
		Provider: "CustomProvider",
	}
	c.ApplyDefaults()

	if c.Provider != "CustomProvider" {
		t.Errorf("expected Provider 'CustomProvider', got %q", c.Provider)
	}
}
