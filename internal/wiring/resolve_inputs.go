package wiring

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func resolveInputs(cfg *config.Config, d *Deps) resolve.ResolveInputs {
	tokenPath := cfg.TokenExchange.Path
	return resolve.ResolveInputs{
		PublicOrigin:        cfg.PublicOrigin,
		ExternalBasePath:    cfg.ExternalBasePath,
		TokenExchangePath:   tokenPath,
		KeyManager:          d.KeyManager,
		OpenCloudMeshPolicy: d.OpenCloudMeshPolicy,
		RuntimePolicy:       d.RuntimePolicy,
		UIWayfEnabled:       resolve.UIWayfEnabledFromConfig(cfg.HTTP.Services["ui"]),
	}
}
