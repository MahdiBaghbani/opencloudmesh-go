package wiring

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func resolveInputs(cfg *config.Config, d *Deps) resolve.ResolveInputs {
	tokenPath := cfg.TokenExchange.Path
	return resolve.ResolveInputs{
		LocalIdentity:     d.LocalIdentity,
		RouteOpts:         service.RouteOptsFromConfig(cfg),
		TokenExchangePath: tokenPath,
		KeyManager:        d.KeyManager,
		CodeFlow:          d.CodeFlow,
	}
}
