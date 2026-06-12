package wiringtest

import (
	"fmt"
	"io"
	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// DiscardLogger returns a logger that discards output at error level or above.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// DevOrigin builds a PublicOrigin for a given test port.
func DevOrigin(port int) string {
	return fmt.Sprintf("http://localhost:%d", port)
}

// DevConfigNoSignatures returns DevConfig with signature modes off and a test origin.
func DevConfigNoSignatures(port int) *config.Config {
	cfg := config.DevConfig()
	cfg.PublicOrigin = DevOrigin(port)
	cfg.Signature.InboundMode = "off"
	cfg.Signature.OutboundMode = "off"
	return cfg
}

// DevConfigHarness returns DevConfig with a test origin for harness-style bootstrap.
func DevConfigHarness(port int) *config.Config {
	cfg := config.DevConfig()
	cfg.PublicOrigin = DevOrigin(port)
	return cfg
}
