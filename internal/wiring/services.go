package wiring

import (
	"fmt"
	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/server"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocmaux"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/wellknown"
)

type coreServiceBuilder func(
	*config.Config,
	map[string]any,
	*slog.Logger,
	*Deps,
) (service.Service, error)

// coreServiceBuilders maps descriptor Build keys to wiring constructors.
var coreServiceBuilders = map[service.BuildKey]coreServiceBuilder{
	service.BuildWellknown: buildWellknownService,
	service.BuildOCM:       buildOCMService,
	service.BuildOCMAux:    buildOCMAuxService,
	service.BuildAPI:       buildAPIService,
	service.BuildUI:        buildUIService,
	service.BuildWebDAV:    buildWebDAVService,
}

// RegisteredBuildKeys returns the build keys wired in this package.
func RegisteredBuildKeys() []service.BuildKey {
	keys := make([]service.BuildKey, 0, len(coreServiceBuilders))
	for k := range coreServiceBuilders {
		keys = append(keys, k)
	}
	return keys
}

func CoreServiceNames() []string {
	names := make([]string, len(service.Descriptors()))
	for i, d := range service.Descriptors() {
		names[i] = d.Name
	}
	return names
}

func BuildCoreServices(cfg *config.Config, logger *slog.Logger, d *Deps) (map[string]service.Service, error) {
	if d == nil {
		return nil, server.ErrMissingServerDeps
	}
	if d.RealIP == nil {
		return nil, server.ErrMissingRealIP
	}

	descs := service.Descriptors()
	services := make(map[string]service.Service, len(descs))
	for _, desc := range descs {
		if desc.Build == "" {
			return nil, fmt.Errorf("descriptor %q has no build key", desc.Name)
		}
		build, ok := coreServiceBuilders[desc.Build]
		if !ok {
			return nil, fmt.Errorf("no builder registered for service %q (build key %q)", desc.Name, desc.Build)
		}
		svcCfg := cfg.BuildServiceConfig(desc.Name)
		if svcCfg == nil {
			svcCfg = make(map[string]any)
		}
		svc, err := build(cfg, svcCfg, logger, d)
		if err != nil {
			return nil, fmt.Errorf("create service %q: %w", desc.Name, err)
		}
		services[desc.Name] = svc
	}
	return services, nil
}

func ratelimitInputs(d *Deps) ratelimit.Inputs {
	return ratelimit.Inputs{
		Cache:   d.Cache,
		KeyFunc: d.RealIP.GetClientIPString,
	}
}

func buildWellknownService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *Deps) (service.Service, error) {
	return wellknown.New(wellknown.Inputs{
		Resolve:             resolveInputs(cfg, d),
		KeyManager:          d.KeyManager,
		SignatureMiddleware: d.SignatureMiddleware,
	}, svcCfg, log)
}

func buildOCMService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *Deps) (service.Service, error) {
	tokenPath := cfg.TokenExchange.Path
	if tokenPath == "" {
		tokenPath = "token"
	}
	peerMappingResolver := policy.NewPeerMappingResolver(d.CodeFlow, &cfg.OCM.PeerMapping, cfg.OCM.CompatibilityScope)
	return ocm.New(ocm.Inputs{
		IncomingShareRepo:   d.IncomingShareRepo,
		OutgoingShareRepo:   d.OutgoingShareRepo,
		OutgoingInviteRepo:  d.OutgoingInviteRepo,
		PartyRepo:           d.PartyRepo,
		PolicyEngine:        d.PolicyEngine,
		CodeFlow:            d.CodeFlow,
		PeerMappingResolver: peerMappingResolver,
		LocalIdentity:       d.LocalIdentity,
		TokenStore:          d.TokenStore,
		SignatureMiddleware: d.SignatureMiddleware,
		TokenExchangePath:   tokenPath,
	}, svcCfg, log)
}

func buildOCMAuxService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *Deps) (service.Service, error) {
	var profiles map[string]map[string]any
	if cfg.HTTP.Interceptors != nil {
		profiles = cfg.HTTP.Interceptors
	}
	return ocmaux.New(ocmaux.Inputs{
		TrustGroupMgr:       d.TrustGroupMgr,
		DiscoveryClient:     d.DiscoveryClient,
		Ratelimit:           ratelimitInputs(d),
		InterceptorProfiles: profiles,
	}, svcCfg, log)
}

func buildAPIService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *Deps) (service.Service, error) {
	var profiles map[string]map[string]any
	if cfg.HTTP.Interceptors != nil {
		profiles = cfg.HTTP.Interceptors
	}

	peerMappingResolver := policy.NewPeerMappingResolver(d.CodeFlow, &cfg.OCM.PeerMapping, cfg.OCM.CompatibilityScope)

	// Use the same production provider config that wellknown.New resolves for
	// discovery, so the API service token endpoint stays in lock-step with the
	// published discovery document.
	var rawOCMProvider map[string]any
	if wellknownSvcCfg := cfg.BuildServiceConfig("wellknown"); wellknownSvcCfg != nil {
		if om, ok := wellknownSvcCfg["ocmprovider"].(map[string]any); ok {
			rawOCMProvider = om
		}
	}
	var providerCfg resolve.ProviderConfig
	if rawOCMProvider != nil {
		if err := svccfg.Decode(rawOCMProvider, &providerCfg); err != nil {
			return nil, fmt.Errorf("api: decode ocm provider config: %w", err)
		}
	}
	resolved := resolve.Resolve(&providerCfg, rawOCMProvider, resolveInputs(cfg, d))
	localTokenEndpoint := resolved.Params.TokenEndPoint

	return api.New(api.Inputs{
		PartyRepo:             d.PartyRepo,
		SessionRepo:           d.SessionRepo,
		UserAuth:              d.UserAuth,
		IncomingShareRepo:     d.IncomingShareRepo,
		OutgoingShareRepo:     d.OutgoingShareRepo,
		IncomingInviteRepo:    d.IncomingInviteRepo,
		OutgoingInviteRepo:    d.OutgoingInviteRepo,
		HTTPClient:            d.HTTPClient,
		DiscoveryClient:       d.DiscoveryClient,
		Signer:                d.Signer,
		PeerOrigin:            d.PeerOrigin,
		OutgoingFactsResolver: peerMappingResolver,
		LocalTokenEndpoint:    localTokenEndpoint,
		LocalIdentity:         d.LocalIdentity,
		Ratelimit:             ratelimitInputs(d),
		InterceptorProfiles:   profiles,
	}, svcCfg, log)
}

func buildUIService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *Deps) (service.Service, error) {
	return ui.New(ui.Inputs{
		LocalIdentity: d.LocalIdentity,
	}, svcCfg, log)
}

func buildWebDAVService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *Deps) (service.Service, error) {
	return webdav.New(webdav.Inputs{
		OutgoingShareRepo: d.OutgoingShareRepo,
		TokenStore:        d.TokenStore,
	}, svcCfg, log)
}
