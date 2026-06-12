package wellknown

import (
	"log/slog"
	"os"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func testResolveIn(in resolve.ResolveInputs) resolve.ResolveInputs {
	return in
}

func testResolveInFromConfig(cfg *config.Config) resolve.ResolveInputs {
	if cfg == nil {
		return resolve.ResolveInputs{}
	}
	return resolve.ResolveInputs{
		PublicOrigin:      cfg.PublicOrigin,
		ExternalBasePath:  cfg.ExternalBasePath,
		TokenExchangePath: cfg.TokenExchange.Path,
		UIWayfEnabled:     resolve.UIWayfEnabledFromConfig(cfg.HTTP.Services["ui"]),
	}
}

func testWellknownInputs(in resolve.ResolveInputs) Inputs {
	return Inputs{Resolve: in}
}

func testWellknownInputsWithEndpoint(endpoint string) Inputs {
	return Inputs{Resolve: resolve.ResolveInputs{PublicOrigin: endpoint}}
}
