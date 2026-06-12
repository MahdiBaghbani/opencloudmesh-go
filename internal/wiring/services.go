package wiring

import (
	"fmt"
	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/server"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocmaux"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/wellknown"
)

type coreServiceEntry struct {
	name  string
	build func(*config.Config, map[string]any, *slog.Logger, *deps.Deps) (service.Service, error)
}

var coreServiceTable = []coreServiceEntry{
	{name: "wellknown", build: buildWellknownService},
	{name: "ocm", build: buildOCMService},
	{name: "ocmaux", build: buildOCMAuxService},
	{name: "api", build: buildAPIService},
	{name: "ui", build: buildUIService},
	{name: "webdav", build: buildWebDAVService},
}

func CoreServiceNames() []string {
	names := make([]string, len(coreServiceTable))
	for i, entry := range coreServiceTable {
		names[i] = entry.name
	}
	return names
}

func BuildCoreServices(cfg *config.Config, logger *slog.Logger) (map[string]service.Service, error) {
	d := deps.GetDeps()
	if d == nil {
		return nil, server.ErrMissingServerDeps
	}
	if d.RealIP == nil {
		return nil, server.ErrMissingRealIP
	}

	services := make(map[string]service.Service, len(coreServiceTable))
	for _, entry := range coreServiceTable {
		svcCfg := cfg.BuildServiceConfig(entry.name)
		if svcCfg == nil {
			svcCfg = make(map[string]any)
		}
		svc, err := entry.build(cfg, svcCfg, logger, d)
		if err != nil {
			return nil, fmt.Errorf("create service %q: %w", entry.name, err)
		}
		services[entry.name] = svc
	}
	return services, nil
}

func ratelimitInputs(d *deps.Deps) ratelimit.Inputs {
	return ratelimit.Inputs{
		Cache:   d.Cache,
		KeyFunc: d.RealIP.GetClientIPString,
	}
}

func buildWellknownService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *deps.Deps) (service.Service, error) {
	return wellknown.New(wellknown.Inputs{
		Resolve: resolveInputs(cfg, d),
	}, svcCfg, log)
}

func buildOCMService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *deps.Deps) (service.Service, error) {
	tokenPath := cfg.TokenExchange.Path
	if tokenPath == "" {
		tokenPath = "token"
	}
	return ocm.New(ocm.Inputs{
		IncomingShareRepo:           d.IncomingShareRepo,
		OutgoingShareRepo:           d.OutgoingShareRepo,
		OutgoingInviteRepo:          d.OutgoingInviteRepo,
		PartyRepo:                   d.PartyRepo,
		PolicyEngine:                d.PolicyEngine,
		DiscoveryClient:             d.DiscoveryClient,
		OpenCloudMeshPolicy:         d.OpenCloudMeshPolicy,
		RuntimePolicy:               d.RuntimePolicy,
		PeerContract:                d.PeerContract,
		LocalProviderFQDN:           d.LocalProviderFQDN,
		LocalProviderFQDNForCompare: d.LocalProviderFQDNForCompare,
		TokenStore:                  d.TokenStore,
		SignatureMiddleware:         d.SignatureMiddleware,
		PublicOrigin:                cfg.PublicOrigin,
		PublicScheme:                cfg.PublicScheme(),
		TokenExchangePath:           tokenPath,
	}, svcCfg, log)
}

func buildOCMAuxService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *deps.Deps) (service.Service, error) {
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

func buildAPIService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *deps.Deps) (service.Service, error) {
	var profiles map[string]map[string]any
	if cfg.HTTP.Interceptors != nil {
		profiles = cfg.HTTP.Interceptors
	}
	return api.New(api.Inputs{
		PartyRepo:           d.PartyRepo,
		SessionRepo:         d.SessionRepo,
		UserAuth:            d.UserAuth,
		IncomingShareRepo:   d.IncomingShareRepo,
		OutgoingShareRepo:   d.OutgoingShareRepo,
		IncomingInviteRepo:  d.IncomingInviteRepo,
		OutgoingInviteRepo:  d.OutgoingInviteRepo,
		HTTPClient:          d.HTTPClient,
		DiscoveryClient:     d.DiscoveryClient,
		Signer:              d.Signer,
		OutboundPolicy:      d.OutboundPolicy,
		OpenCloudMeshPolicy: d.OpenCloudMeshPolicy,
		PeerContract:        d.PeerContract,
		LocalProviderFQDN:   d.LocalProviderFQDN,
		Ratelimit:           ratelimitInputs(d),
		InterceptorProfiles: profiles,
	}, svcCfg, log)
}

func buildUIService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *deps.Deps) (service.Service, error) {
	return ui.New(ui.Inputs{
		ExternalBasePath:  cfg.ExternalBasePath,
		LocalProviderFQDN: d.LocalProviderFQDN,
	}, svcCfg, log)
}

func buildWebDAVService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *deps.Deps) (service.Service, error) {
	return webdav.New(webdav.Inputs{
		OutgoingShareRepo: d.OutgoingShareRepo,
		TokenStore:        d.TokenStore,
		PeerContract:      d.PeerContract,
	}, svcCfg, log)
}
