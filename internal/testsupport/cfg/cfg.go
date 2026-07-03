package cfg

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// DevConfigNoSignatures returns DevConfig with signature modes off.
func DevConfigNoSignatures() *config.Config {
	c := config.DevConfig()
	c.Signature.InboundMode = "off"
	c.Signature.OutboundMode = "off"
	return c
}

// DevConfigHarness returns DevConfig for harness-style bootstrap.
func DevConfigHarness() *config.Config {
	return config.DevConfig()
}
