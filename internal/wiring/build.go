// Package wiring is the composition root for opencloudmesh-go process startup.
package wiring

import (
	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/app"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// BuildOpts controls which optional infrastructure wiring builds.
// During the bootstrap cutover window this aliases app.WireOptions.
type BuildOpts = app.WireOptions

// BuildResult holds values callers need after wiring completes.
// During the bootstrap cutover window this aliases app.BootstrapResult.
type BuildResult = app.BootstrapResult

// Build wires shared infrastructure and calls deps.SetDeps.
// Callers own config loading, logger setup, admin bootstrapping, posture
// checks, and server lifecycle. Test callers must call deps.ResetDeps before
// Build when re-wiring in the same process.
func Build(cfg *config.Config, logger *slog.Logger, opts BuildOpts) (BuildResult, error) {
	return app.BootstrapDeps(cfg, logger, opts)
}
