// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"fmt"
	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/forwardshare"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseinvite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseshare"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outbound"
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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/validator"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/wellknown"
)

// validatorLegs carries the active-session validator services built once per
// process (when the validator store exists) and handed to every builder; only
// the ocm decorator, the validator paste route, and the api outgoing-share
// dispatch hook consume them.
type validatorLegs struct {
	reverseInvite *reverseinvite.Service
	forwardShare  *forwardshare.Service
	reverseShare  *reverseshare.Service
}

// coreServiceBuilder builds one core service from config, logger, deps, and
// the shared validator legs (nil outside validator mode).
type coreServiceBuilder func(
	*config.Config,
	map[string]any,
	*slog.Logger,
	*Deps,
	*validatorLegs,
) (service.Service, error)

// coreServiceBuilders maps descriptor Build keys to wiring constructors.
var coreServiceBuilders = map[service.BuildKey]coreServiceBuilder{
	service.BuildWellknown: buildWellknownService,
	service.BuildOCM:       buildOCMService,
	service.BuildOCMAux:    buildOCMAuxService,
	service.BuildAPI:       buildAPIService,
	service.BuildUI:        buildUIService,
	service.BuildWebDAV:    buildWebDAVService,
	service.BuildValidator: buildValidatorService,
}

// RegisteredBuildKeys returns the build keys wired in this package.
func RegisteredBuildKeys() []service.BuildKey {
	keys := make([]service.BuildKey, 0, len(coreServiceBuilders))
	for k := range coreServiceBuilders {
		keys = append(keys, k)
	}

	return keys
}

// CoreServiceNames returns the names of all registered service descriptors.
func CoreServiceNames() []string {
	names := make([]string, len(service.Descriptors()))
	for i, d := range service.Descriptors() {
		names[i] = d.Name
	}

	return names
}

// BuildCoreServices constructs the core services from config, logger, and dependencies.
func BuildCoreServices(cfg *config.Config, logger *slog.Logger, d *Deps) (map[string]service.Service, error) {
	if d == nil {
		return nil, server.ErrMissingServerDeps
	}

	if d.RealIP == nil {
		return nil, server.ErrMissingRealIP
	}

	// In validator mode the active-session legs are built once up front and
	// shared by the ocm decorator, the validator paste route, and the api
	// outgoing-share dispatch hook. A construction failure is a boot error,
	// never a silently missing route.
	var legs *validatorLegs

	if d.ValidatorStore != nil {
		built, err := buildValidatorLegs(d, logger)
		if err != nil {
			return nil, err
		}

		legs = built
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

		svc, err := build(cfg, svcCfg, logger, d, legs)
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

func buildWellknownService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *Deps, _ *validatorLegs) (service.Service, error) {
	svc, err := wellknown.New(wellknown.Inputs{
		Resolve:             resolveInputs(cfg, d),
		SignatureMiddleware: d.SignatureMiddleware,
	}, svcCfg, log)
	if err != nil {
		return nil, fmt.Errorf("wiring: wire wellknown service: %w", err)
	}

	return svc, nil
}

func buildOCMService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *Deps, legs *validatorLegs) (service.Service, error) {
	tokenPath := cfg.TokenExchange.Path
	if tokenPath == "" {
		tokenPath = "token"
	}

	peerMappingResolver := policy.NewPeerMappingResolver(d.CodeFlow, &cfg.OCM.PeerMapping, cfg.OCM.CompatibilityScope)

	inputs := ocm.Inputs{
		IncomingShareRepo:   d.IncomingShareRepo,
		OutgoingShareRepo:   d.OutgoingShareRepo,
		IncomingInviteRepo:  d.IncomingInviteRepo,
		OutgoingInviteRepo:  d.OutgoingInviteRepo,
		PartyRepo:           d.PartyRepo,
		PolicyEngine:        d.PolicyEngine,
		CodeFlow:            d.CodeFlow,
		PeerMappingResolver: peerMappingResolver,
		LocalIdentity:       d.LocalIdentity,
		TokenStore:          d.TokenStore,
		SignatureMiddleware: d.SignatureMiddleware,
		TokenExchangePath:   tokenPath,
		KeyManager:          d.KeyManager,
		MustInviteEnforced:  cfg.OCM.MustInviteEnforced(),
	}

	// In validator mode the invite-accepted protocol endpoint is wrapped from
	// outside so the validator can observe acceptances; the product handler
	// stays unaware of test runs.
	if legs != nil && legs.reverseInvite != nil {
		inputs.InviteAcceptedDecorator = legs.reverseInvite.DecorateInviteAccepted
	}

	// The inbound share observer lets the validator pass runs on the peer's
	// reverse share; the product handler stays unaware of test runs.
	if legs != nil && legs.reverseShare != nil {
		inputs.IncomingShareObserver = legs.reverseShare.ObserveCreatedShare
		inputs.TokenExchangeObserver = legs.reverseShare.ObserveTokenExchange
	}

	svc, err := ocm.New(inputs, svcCfg, log)
	if err != nil {
		return nil, fmt.Errorf("wiring: wire ocm service: %w", err)
	}

	return svc, nil
}

// buildValidatorLegs assembles the active-session validator legs on the
// shared stores: the reverse-invite orchestration on the live outbound
// poster, and the forward-share dispatch guard on the outgoing share repo.
func buildValidatorLegs(d *Deps, log *slog.Logger) (*validatorLegs, error) {
	poster := api.NewInviteAcceptedPoster(outbound.NewPoster(
		d.HTTPClient,
		d.DiscoveryClient,
		d.Signer,
		d.PeerOrigin,
	))

	reverseSvc, err := reverseinvite.New(reverseinvite.Deps{
		Store:           d.ValidatorStore,
		OutgoingInvites: d.OutgoingInviteRepo,
		IncomingInvites: d.IncomingInviteRepo,
		Parties:         d.PartyRepo,
		Poster:          poster,
		LocalIdentity:   d.LocalIdentity,
		Logger:          log,
	})
	if err != nil {
		return nil, fmt.Errorf("wiring: build reverse invite service: %w", err)
	}

	forwardSvc, err := forwardshare.New(forwardshare.Deps{
		Store:          d.ValidatorStore,
		OutgoingShares: d.OutgoingShareRepo,
		LocalIdentity:  d.LocalIdentity,
	})
	if err != nil {
		return nil, fmt.Errorf("wiring: build forward share service: %w", err)
	}

	reverseShareSvc, err := reverseshare.New(reverseshare.Deps{
		Store:          d.ValidatorStore,
		IncomingShares: d.IncomingShareRepo,
		LocalIdentity:  d.LocalIdentity,
		Logger:         log,
	})
	if err != nil {
		return nil, fmt.Errorf("wiring: build reverse share service: %w", err)
	}

	return &validatorLegs{
		reverseInvite: reverseSvc,
		forwardShare:  forwardSvc,
		reverseShare:  reverseShareSvc,
	}, nil
}

func buildOCMAuxService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *Deps, _ *validatorLegs) (service.Service, error) {
	var profiles map[string]map[string]any
	if cfg.HTTP.Interceptors != nil {
		profiles = cfg.HTTP.Interceptors
	}

	svc, err := ocmaux.New(ocmaux.Inputs{
		TrustGroupMgr:       d.TrustGroupMgr,
		DiscoveryClient:     d.DiscoveryClient,
		Ratelimit:           ratelimitInputs(d),
		InterceptorProfiles: profiles,
	}, svcCfg, log)
	if err != nil {
		return nil, fmt.Errorf("wiring: wire ocm auxiliary service: %w", err)
	}

	return svc, nil
}

func buildAPIService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *Deps, legs *validatorLegs) (service.Service, error) {
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

	inputs := api.Inputs{
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
		ContentDir:            cfg.Persistence.ContentDir,
		Ratelimit:             ratelimitInputs(d),
		InterceptorProfiles:   profiles,
	}

	// In validator mode the outgoing-share handler gains the dispatch policy
	// guard; outside validator mode the hook seat stays empty and the generic
	// flow is unchanged.
	if legs != nil && legs.forwardShare != nil {
		inputs.OutgoingDispatchHook = legs.forwardShare
	}

	svc, err := api.New(inputs, svcCfg, log)
	if err != nil {
		return nil, fmt.Errorf("wiring: wire api service: %w", err)
	}

	return svc, nil
}

func buildUIService(_ *config.Config, svcCfg map[string]any, log *slog.Logger, d *Deps, _ *validatorLegs) (service.Service, error) {
	svc, err := ui.New(ui.Inputs{
		LocalIdentity: d.LocalIdentity,
	}, svcCfg, log)
	if err != nil {
		return nil, fmt.Errorf("wiring: wire ui service: %w", err)
	}

	return svc, nil
}

func buildWebDAVService(_ *config.Config, svcCfg map[string]any, log *slog.Logger, d *Deps, legs *validatorLegs) (service.Service, error) {
	inputs := webdav.Inputs{
		OutgoingShareRepo: d.OutgoingShareRepo,
		TokenStore:        d.TokenStore,
	}

	// The share-access observer lets the validator open the reverse-share
	// wait on the peer's authorized GET; the product handler stays unaware
	// of test runs.
	if legs != nil && legs.reverseShare != nil {
		inputs.ShareAccessObserver = legs.reverseShare.ObserveWebDAVGet
	}

	svc, err := webdav.New(inputs, svcCfg, log)
	if err != nil {
		return nil, fmt.Errorf("wiring: wire webdav service: %w", err)
	}

	return svc, nil
}

func buildValidatorService(cfg *config.Config, svcCfg map[string]any, log *slog.Logger, d *Deps, legs *validatorLegs) (service.Service, error) {
	var profiles map[string]map[string]any
	if cfg.HTTP.Interceptors != nil {
		profiles = cfg.HTTP.Interceptors
	}

	var reverseSvc *reverseinvite.Service

	var reverseShareSvc *reverseshare.Service

	if legs != nil {
		reverseSvc = legs.reverseInvite
		reverseShareSvc = legs.reverseShare
	}

	svc, err := validator.New(validator.Inputs{
		Store:               d.ValidatorStore,
		FedCore:             d.ValidatorCore,
		DiscoveryClient:     d.DiscoveryClient,
		Config:              cfg,
		Ratelimit:           ratelimitInputs(d),
		InterceptorProfiles: profiles,
		Log:                 log,
		ReverseInvite:       reverseSvc,
		ReverseShare:        reverseShareSvc,
		PartyRepo:           d.PartyRepo,
		LocalProviderDomain: d.LocalIdentity.ProviderDomain,
	}, svcCfg, log)
	if err != nil {
		return nil, fmt.Errorf("wiring: wire validator service: %w", err)
	}

	return svc, nil
}
