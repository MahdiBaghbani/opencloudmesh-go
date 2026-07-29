package wiring

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func resolveInputs(cfg *config.Config, d *Deps) resolve.ResolveInputs {
	tokenPath := cfg.TokenExchange.Path
	resolver := policy.NewPeerMappingResolver(d.CodeFlow, &cfg.OCM.PeerMapping, cfg.OCM.CompatibilityScope)

	return resolve.ResolveInputs{
		LocalIdentity:     d.LocalIdentity,
		RouteOpts:         service.RouteOptsFromConfig(cfg),
		TokenExchangePath: tokenPath,
		KeyManager:        d.KeyManager,
		CodeFlow:          d.CodeFlow,
		Resolver:          resolver,
		JwksURIOverride:   cfg.Signature.JwksURI,
	}
}
