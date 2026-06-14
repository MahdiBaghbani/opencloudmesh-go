package wellknown

import "testing"

func TestOCMProviderConfig_ApplyDefaults(t *testing.T) {
	c := &OCMProviderConfig{}
	c.ApplyDefaults()

	// ApplyDefaults only sets service-local fields (OCMPrefix, Provider).
	// Cross-cutting fields (WebDAVRoot, TokenExchange) are derived in newOCMHandler.
	if c.OCMPrefix != "ocm" {
		t.Errorf("expected OCMPrefix 'ocm', got %q", c.OCMPrefix)
	}
	if c.Provider != "OpenCloudMesh" {
		t.Errorf("expected Provider 'OpenCloudMesh', got %q", c.Provider)
	}
}

func TestOCMProviderConfig_ApplyDefaults_PreservesCustomValues(t *testing.T) {
	c := &OCMProviderConfig{
		OCMPrefix: "custom-ocm",
		Provider:  "CustomProvider",
	}
	c.ApplyDefaults()

	if c.OCMPrefix != "custom-ocm" {
		t.Errorf("expected OCMPrefix 'custom-ocm', got %q", c.OCMPrefix)
	}
	if c.Provider != "CustomProvider" {
		t.Errorf("expected Provider 'CustomProvider', got %q", c.Provider)
	}
}
