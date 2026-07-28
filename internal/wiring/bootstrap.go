package wiring

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/directoryservice"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
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
	// Persistence.Close() on shutdown; Close is a no-op for the memory backend.
	Persistence *repos.Repos
}

// wireSharedDeps builds shared infrastructure from config and persistence repos.
// persistence must be constructed by wiring.Build via repos.New before calling
// this function.
func wireSharedDeps(cfg *config.Config, logger *slog.Logger, opts BuildOpts, persistence *repos.Repos) (BuildResult, error) {
	if persistence == nil {
		return BuildResult{}, fmt.Errorf("wire shared deps: persistence repos must be non-nil")
	}

	peerOrigin := peerorigin.NewResolver(cfg.TLS.Mode == "off")
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

	partyRepo := identity.NewMemoryPartyRepo()
	sessionRepo := identity.NewMemorySessionRepo()

	userAuth := buildUserAuth(opts)

	keyManager, err := buildKeyManager(cfg, localIdentity, opts, logger)
	if err != nil {
		return BuildResult{}, err
	}

	facts := codeFlow.Evaluate()
	if facts.RequiresHTTPRequestSignatures && keyManager == nil {
		return BuildResult{}, fmt.Errorf("ocm: code flow requires HTTP request signatures but no signing key is configured")
	}

	outboundCfg := resolveOutboundConfig(cfg, opts)

	rootCAPool, err := tlspkg.BuildRootCAPool(outboundCfg.TLSRootCAFile, outboundCfg.TLSRootCADir)
	if err != nil {
		return BuildResult{}, fmt.Errorf("build root CA pool: %w", err)
	}

	rawHTTPClient := httpclient.New(outboundCfg, rootCAPool)
	httpClient := httpclient.NewContextClient(rawHTTPClient)

	cacheInstance, err := buildCacheInstance(cfg)
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

	peerDiscoveryAdapter := discovery.NewPeerDiscoveryAdapter(rawHTTPClient)
	peerDiscoveryAdapter.SetPeerOrigin(peerOrigin)
	signatureMiddleware := signature.NewSignatureMiddleware(
		peerDiscoveryAdapter,
		localIdentity.Origin,
		cfg.Signature,
		logger,
	)
	signatureMiddleware.SetLocalHTTPSigPolicy(facts.RequiresHTTPRequestSignatures, keyManager != nil)

	tokenStore := token.NewMemoryTokenStore()
	realIPExtractor := realip.NewTrustedProxies(cfg.Server.TrustedProxies)

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
		Cache:               cacheInstance,
		RealIP:              realIPExtractor,
	}

	return BuildResult{
		Deps:        built,
		RootCAPool:  rootCAPool,
		Persistence: persistence,
	}, nil
}

func buildUserAuth(opts BuildOpts) *identity.UserAuth {
	if opts.FastAuth {
		return identity.NewUserAuthFast()
	}

	return identity.NewUserAuth()
}

func buildKeyManager(
	cfg *config.Config,
	localIdentity localidentity.Identity,
	opts BuildOpts,
	logger *slog.Logger,
) (*crypto.KeyManager, error) {
	if opts.SkipCrypto {
		return nil, nil //nolint:nilnil // intentional: (nil, nil) denotes crypto skipped; caller checks for a nil KeyManager
	}

	keyDir := filepath.Dir(cfg.Signature.KeyPath)
	if keyDir != "" && keyDir != "." {
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			return nil, fmt.Errorf("create key directory %q: %w", keyDir, err)
		}
	}

	keyManager := crypto.NewKeyManagerWithFragment(
		cfg.Signature.KeyPath,
		localIdentity.Origin,
		cfg.Signature.KidFragment,
	)
	if err := keyManager.LoadOrGenerate(); err != nil {
		return nil, fmt.Errorf("initialize signing key: %w", err)
	}

	logger.Info("initialized signing key", "keyId", keyManager.GetKeyID())

	return keyManager, nil
}

func resolveOutboundConfig(cfg *config.Config, opts BuildOpts) *config.OutboundHTTPConfig {
	if opts.OutboundOverride != nil {
		return opts.OutboundOverride
	}

	return &cfg.OutboundHTTP
}

func buildCacheInstance(cfg *config.Config) (cache.CacheWithCounter, error) {
	cacheDriver := cfg.Cache.Driver
	if cacheDriver == "" {
		cacheDriver = "memory"
	}

	cacheInstance, err := cache.NewFromConfig(cacheDriver, cfg.Cache.Drivers)
	if err != nil {
		return nil, fmt.Errorf("create cache: %w", err)
	}

	return cacheInstance, nil
}

func buildPeerTrust(
	cfg *config.Config,
	localIdentity localidentity.Identity,
	rawHTTPClient *httpclient.Client,
	logger *slog.Logger,
	opts BuildOpts,
) (*peertrust.TrustGroupManager, *peertrust.PolicyEngine, error) { //nolint:unparam // error result kept for builder symmetry; trust-group load failures are logged and skipped by design, so it is always nil today
	if opts.SkipPeerTrust || !cfg.PeerTrust.Enabled {
		return nil, nil, nil
	}

	outboundCfg := resolveOutboundConfig(cfg, opts)
	refreshTimeout := time.Duration(outboundCfg.TimeoutMS) * time.Millisecond
	cacheConfig := peertrust.CacheConfig{
		TTL:      time.Duration(cfg.PeerTrust.MembershipCache.TTLSeconds) * time.Second,
		MaxStale: time.Duration(cfg.PeerTrust.MembershipCache.MaxStaleSeconds) * time.Second,
	}

	dirServiceClient := directoryservice.NewClient(rawHTTPClient, "required", logger)
	trustGroupMgr := peertrust.NewTrustGroupManager(cacheConfig, dirServiceClient, localIdentity.Scheme, logger, refreshTimeout)

	for _, cfgPath := range cfg.PeerTrust.ConfigPaths {
		tgCfg, err := peertrust.LoadTrustGroupConfig(cfgPath)
		if err != nil {
			logger.Warn("failed to load trust group config", "path", cfgPath, "error", err)
			continue
		}

		trustGroupMgr.AddTrustGroup(tgCfg)
		logger.Info("loaded trust group", "trust_group_id", tgCfg.TrustGroupID, "enabled", tgCfg.Enabled)
	}

	policyCfg := &peertrust.PolicyConfig{
		AllowList: cfg.PeerTrust.Policy.AllowList,
		DenyList:  cfg.PeerTrust.Policy.DenyList,
	}
	policyEngine := peertrust.NewPolicyEngine(policyCfg, trustGroupMgr, logger)
	logger.Info("peer trust enabled", "config_paths", len(cfg.PeerTrust.ConfigPaths))

	return trustGroupMgr, policyEngine, nil
}

func buildSigner(cfg *config.Config, keyManager *crypto.KeyManager) *crypto.RFC9421Signer {
	if keyManager == nil {
		return nil
	}

	signerOpts := crypto.RFC9421OptionsFromConfig(cfg.Signature)

	return crypto.NewRFC9421SignerWithOptions(keyManager, signerOpts)
}
