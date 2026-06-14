package cfg

import (
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// DevOrigin builds a PublicOrigin for a given test port.
func DevOrigin(port int) string {
	return fmt.Sprintf("http://localhost:%d", port)
}

// DevConfigNoSignatures returns DevConfig with signature modes off and a test origin.
func DevConfigNoSignatures(port int) *config.Config {
	c := config.DevConfig()
	c.PublicOrigin = DevOrigin(port)
	c.Signature.InboundMode = "off"
	c.Signature.OutboundMode = "off"
	return c
}

// DevConfigHarness returns DevConfig with a test origin for harness-style bootstrap.
func DevConfigHarness(port int) *config.Config {
	c := config.DevConfig()
	c.PublicOrigin = DevOrigin(port)
	return c
}
