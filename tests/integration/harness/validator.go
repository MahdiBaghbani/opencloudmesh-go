// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package harness

import (
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// StartValidatorServer starts an in-process server in validator mode.
// Listen address uses an ephemeral free port (never 43201). Transport stays
// on the existing integration harness baseline (TLS off, harness outbound).
func StartValidatorServer(t *testing.T) *TestServer {
	t.Helper()

	dataDir := t.TempDir()

	return StartTestServerWithConfig(t, func(cfg *config.Config) {
		applyValidatorHarnessConfig(cfg, dataDir)
	})
}

func applyValidatorHarnessConfig(cfg *config.Config, dataDir string) {
	preset := config.ValidatorConfig()

	cfg.Mode = preset.Mode
	cfg.Statistics.Enabled = true
	cfg.Persistence.Backend = config.BackendSQLite
	cfg.Persistence.DataDir = dataDir
	cfg.Persistence.ContentDir = filepath.Join(dataDir, "files")
	cfg.HTTP.Interceptors = preset.HTTP.Interceptors
	cfg.HTTP.Services = preset.HTTP.Services
	cfg.Validator = preset.Validator
	cfg.Server.TrustedProxies = append([]string(nil), preset.Server.TrustedProxies...)
}
