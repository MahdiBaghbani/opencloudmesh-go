// Package wiring is the composition root for opencloudmesh-go process startup.
package wiring

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/app"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
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
// Build when re-wiring in the same process. On BootstrapDeps failure, Build
// closes persistenceRepos before returning the error.
func Build(cfg *config.Config, logger *slog.Logger, opts BuildOpts) (BuildResult, error) {
	persistenceRepos, err := repos.New(context.Background(), cfg.Persistence)
	if err != nil {
		return BuildResult{}, fmt.Errorf("wire persistence repos: %w", err)
	}
	result, err := bootstrapDeps(cfg, logger, opts, persistenceRepos)
	if err != nil {
		closePersistenceOnBootstrapFailure(persistenceRepos, logger)
		return BuildResult{}, fmt.Errorf("bootstrap deps: %w", err)
	}
	return result, nil
}
