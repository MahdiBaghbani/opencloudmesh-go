package wellknown

import "testing"

func TestOCMProviderConfig_ApplyDefaults(t *testing.T) {
	c := &OCMProviderConfig{}
	c.ApplyDefaults()

	if c.Provider != "OpenCloudMesh" {
		t.Errorf("expected Provider 'OpenCloudMesh', got %q", c.Provider)
	}
}

func TestOCMProviderConfig_ApplyDefaults_PreservesCustomValues(t *testing.T) {
	c := &OCMProviderConfig{
		Provider: "CustomProvider",
	}
	c.ApplyDefaults()

	if c.Provider != "CustomProvider" {
		t.Errorf("expected Provider 'CustomProvider', got %q", c.Provider)
	}
}
