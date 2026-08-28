// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tlspkg "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/tls"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
)

// ErrMsgNilDepsAfterBuild is logged when Build returns a nil Deps pointer.
const ErrMsgNilDepsAfterBuild = "Build succeeded but Deps is nil; this is a bug in wiring.Build"

// BuildOpts controls which optional infrastructure wiring builds.
// The zero value matches production wiring (main.go path): full crypto,
// peer trust from config, real argon2id cost, and discovery cache enabled.
type BuildOpts struct {
	// FastAuth uses low-cost argon2id parameters. Set true for tests.
	FastAuth bool

	// SkipCrypto skips KeyManager and Signer construction. Build fails fast when
	// the code flow requires HTTP request signatures but no signing key is
	// configured (RequiresHTTPRequestSignatures && keyManager == nil).
	SkipCrypto bool

	// SkipPeerTrust disables TrustGroupManager and PolicyEngine construction
	// regardless of cfg.PeerTrust.Enabled.
	SkipPeerTrust bool

	// OutboundOverride replaces cfg.OutboundHTTP when non-nil.
	OutboundOverride *config.OutboundHTTPConfig

	// OutboundDialHosts remaps advertised hostnames to dial IPs on the
	// shared outbound client. Test-only; production leaves this nil.
	OutboundDialHosts map[string]string

	// SkipDiscoveryCache wires a no-op cache for the discovery client instead
	// of the shared in-memory cache.
	SkipDiscoveryCache bool
}

// BuildResult holds values built by wiring.Build that callers need after the call.
type BuildResult struct {
	// Deps is the explicit shared dependency graph for service construction.
	Deps *Deps

	// RootCAPool is the built root CA pool (nil = use system TLS defaults).
	RootCAPool *x509.CertPool

	// Persistence holds the wired persistence repos. Callers must call
	// Persistence.Close() on shutdown after StopRetentionSweep when that
	// stop func is non-nil. Close is a no-op for the memory backend.
	Persistence *repos.Repos

	// StopRetentionSweep cancels the store-level maintenance tickers started
	// after a successful Attach (the permanent-report expiry loop and the
	// stalled active-run sweep) plus any late-started seats such as the
	// active runner, and waits for those goroutines to return.
	// Nil when the validator store is not wired.
	// Call on process shutdown before Persistence.Close.
	StopRetentionSweep context.CancelFunc
}

// wireSharedDeps builds shared infrastructure from config and persistence repos.
// persistence must be constructed by wiring.Build via repos.New before calling
// this function.
func wireSharedDeps(cfg *config.Config, logger *slog.Logger, opts BuildOpts, persistence *repos.Repos) (BuildResult, error) {
	if persistence == nil {
		return BuildResult{}, errors.New("wire shared deps: persistence repos must be non-nil")
	}

	peerOrigin := peerorigin.NewResolver(cfg.TLS.Mode == config.TLSModeOff)
	codeFlow := &policy.CodeFlow{
		IncludesTokenExchangeRequirement: cfg.OCM.CodeFlow.IncludesTokenExchangeRequirement,
		RequiresTokenExchangeRequirement: cfg.OCM.CodeFlow.RequiresTokenExchangeRequirement,
		RequiresHTTPRequestSignatures:    cfg.OCM.CodeFlow.RequiresHTTPRequestSignatures,
	}
	versionPolicy := discovery.VersionPolicyFromConfig(cfg.OCM.Discovery)

	localIdentity, err := localidentity.Derive(cfg.PublicOrigin, cfg.ExternalBasePath)
	if err != nil {
		return BuildResult{}, fmt.Errorf("derive local public identity: %w", err)
	}

	cfg.ExternalBasePath = localIdentity.ExternalBasePath

	if validateErr := discovery.ValidateLocalJwksURIOverride(cfg.Signature.JwksURI, localIdentity.Origin); validateErr != nil {
		return BuildResult{}, fmt.Errorf("invalid signature.jwks_uri: %w", validateErr)
	}

	partyRepo := identity.NewMemoryPartyRepo()
	sessionRepo := identity.NewMemorySessionRepo()

	userAuth := buildUserAuth(opts)

	keyManager, err := buildKeyManager(cfg, localIdentity, opts, logger)
	if err != nil {
		return BuildResult{}, err
	}

	facts := codeFlow.Evaluate()
	if facts.RequiresHTTPRequestSignatures && keyManager == nil {
		return BuildResult{}, errors.New("ocm: code flow requires HTTP request signatures but no signing key is configured")
	}

	outboundCfg := resolveOutboundConfig(cfg, opts)

	rootCAPool, err := tlspkg.BuildRootCAPool(outboundCfg.TLSRootCAFile, outboundCfg.TLSRootCADir)
	if err != nil {
		return BuildResult{}, fmt.Errorf("build root CA pool: %w", err)
	}

	rawHTTPClient := httpclient.New(outboundCfg, rootCAPool)
	rawHTTPClient.SetDialHosts(opts.OutboundDialHosts)
	httpClient := httpclient.NewContextClient(rawHTTPClient)

	cacheInstance, err := buildCacheInstance(cfg)
	if err != nil {
		return BuildResult{}, err
	}

	ratelimitCacheInstance, err := buildRatelimitCacheInstance(cfg)
	if err != nil {
		return BuildResult{}, err
	}

	discoveryCache := cache.Cache(cacheInstance)
	if opts.SkipDiscoveryCache {
		discoveryCache = cache.NewNoopCache()
	}

	discoveryClient := discovery.NewClient(rawHTTPClient, discoveryCache)
	discoveryClient.SetVersionPolicy(versionPolicy)
	discoveryClient.SetLogger(logger)

	trustGroupMgr, policyEngine, err := buildPeerTrust(cfg, localIdentity, rawHTTPClient, logger, opts)
	if err != nil {
		return BuildResult{}, err
	}

	signer := buildSigner(cfg, keyManager)

	peerDiscoveryAdapter := discovery.NewPeerDiscoveryAdapter(rawHTTPClient, discoveryClient)
	peerDiscoveryAdapter.SetPeerOrigin(peerOrigin)

	signatureMiddleware := signature.NewSignatureMiddleware(
		peerDiscoveryAdapter,
		localIdentity.Origin,
		cfg.Signature,
		logger,
	)
	signatureMiddleware.SetLocalHTTPSigPolicy(facts.RequiresHTTPRequestSignatures, keyManager != nil)

	tokenStore := token.NewMemoryTokenStore()

	realIPExtractor, err := buildRealIPExtractor(cfg)
	if err != nil {
		return BuildResult{}, err
	}

	validatorCore, validatorStore, err := buildValidatorPersistence(cfg, persistence)
	if err != nil {
		return BuildResult{}, err
	}

	lateStops := newLateSweepStops(validatorStore)

	built := &Deps{
		PartyRepo:           partyRepo,
		SessionRepo:         sessionRepo,
		UserAuth:            userAuth,
		IncomingShareRepo:   persistence.IncomingShares,
		OutgoingShareRepo:   persistence.OutgoingShares,
		OutgoingInviteRepo:  persistence.OutgoingInvites,
		IncomingInviteRepo:  persistence.IncomingInvites,
		TokenStore:          tokenStore,
		HTTPClient:          httpClient,
		DiscoveryClient:     discoveryClient,
		CodeFlow:            codeFlow,
		KeyManager:          keyManager,
		Signer:              signer,
		SignatureMiddleware: signatureMiddleware,
		TrustGroupMgr:       trustGroupMgr,
		PolicyEngine:        policyEngine,
		PeerOrigin:          peerOrigin,
		LocalIdentity:       localIdentity,
		Config:              cfg,
		Cache:               ratelimitCacheInstance,
		RealIP:              realIPExtractor,
		ValidatorCore:       validatorCore,
		ValidatorStore:      validatorStore,
		lateStops:           lateStops,
	}

	return BuildResult{
		Deps:               built,
		RootCAPool:         rootCAPool,
		Persistence:        persistence,
		StopRetentionSweep: joinStoreSweepStops(startRetentionSweep(validatorStore), startStallSweep(validatorStore), lateStops.Stop),
	}, nil
}
