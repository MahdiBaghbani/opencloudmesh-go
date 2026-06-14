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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
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

	// SkipCrypto disables KeyManager, Signer, and OutboundPolicy construction.
	SkipCrypto bool

	// SkipPeerTrust disables TrustGroupManager and PolicyEngine construction
	// regardless of cfg.PeerTrust.Enabled.
	SkipPeerTrust bool

	// SkipSignatureMiddleware disables SignatureMiddleware construction.
	SkipSignatureMiddleware bool

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

	// RuntimeEval is the pre-computed runtime posture snapshot.
	RuntimeEval policy.RuntimeEvaluation

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

	peerContract, err := peercompat.NewCompiledContractFromConfig(cfg)
	if err != nil {
		return BuildResult{}, fmt.Errorf("compile peer compatibility contract: %w", err)
	}
	openCloudMeshPolicy := policy.NewOpenCloudMeshPolicy(cfg)
	runtimePolicy := policy.NewRuntimePolicy(cfg, peerContract)
	runtimeEval := runtimePolicy.Evaluate()

	localIdentity, err := localidentity.Derive(cfg.PublicOrigin, cfg.ExternalBasePath)
	if err != nil {
		return BuildResult{}, fmt.Errorf("derive local public identity: %w", err)
	}
	cfg.ExternalBasePath = localIdentity.ExternalBasePath

	partyRepo := identity.NewMemoryPartyRepo()
	sessionRepo := identity.NewMemorySessionRepo()
	var userAuth *identity.UserAuth
	if opts.FastAuth {
		userAuth = identity.NewUserAuthFast()
	} else {
		userAuth = identity.NewUserAuth(3)
	}

	var keyManager *crypto.KeyManager
	if !opts.SkipCrypto {
		needsKeys := cfg.Signature.InboundMode != "off" || cfg.Signature.OutboundMode != "off"
		if needsKeys {
			keyDir := filepath.Dir(cfg.Signature.KeyPath)
			if keyDir != "" && keyDir != "." {
				if err := os.MkdirAll(keyDir, 0700); err != nil {
					return BuildResult{}, fmt.Errorf("create key directory %q: %w", keyDir, err)
				}
			}
			keyManager = crypto.NewKeyManager(cfg.Signature.KeyPath, localIdentity.Origin)
			if err := keyManager.LoadOrGenerate(); err != nil {
				return BuildResult{}, fmt.Errorf("initialize signing key: %w", err)
			}
			logger.Info("initialized signing key", "keyId", keyManager.GetKeyID())
		}
	}

	outboundCfg := &cfg.OutboundHTTP
	if opts.OutboundOverride != nil {
		outboundCfg = opts.OutboundOverride
	}

	rootCAPool, err := tlspkg.BuildRootCAPool(outboundCfg.TLSRootCAFile, outboundCfg.TLSRootCADir)
	if err != nil {
		return BuildResult{}, fmt.Errorf("build root CA pool: %w", err)
	}

	rawHTTPClient := httpclient.New(outboundCfg, rootCAPool)
	httpClient := httpclient.NewContextClient(rawHTTPClient)

	cacheDriver := cfg.Cache.Driver
	if cacheDriver == "" {
		cacheDriver = "memory"
	}
	cacheInstance, err := cache.NewFromConfig(cacheDriver, cfg.Cache.Drivers)
	if err != nil {
		return BuildResult{}, fmt.Errorf("create cache: %w", err)
	}

	var discoveryCache cache.Cache
	if opts.SkipDiscoveryCache {
		discoveryCache = cache.NewNoopCache()
	} else {
		discoveryCache = cacheInstance
	}
	discoveryClient := discovery.NewClient(rawHTTPClient, discoveryCache)
	discoveryClient.SetPeerContract(peerContract)

	var trustGroupMgr *peertrust.TrustGroupManager
	var policyEngine *peertrust.PolicyEngine
	if !opts.SkipPeerTrust && cfg.PeerTrust.Enabled {
		refreshTimeout := time.Duration(outboundCfg.TimeoutMS) * time.Millisecond
		cacheConfig := peertrust.CacheConfig{
			TTL:      time.Duration(cfg.PeerTrust.MembershipCache.TTLSeconds) * time.Second,
			MaxStale: time.Duration(cfg.PeerTrust.MembershipCache.MaxStaleSeconds) * time.Second,
		}

		defaultVerificationPolicy := runtimePolicy.DirectoryServiceVerificationPolicy()
		dirServiceClient := directoryservice.NewClient(rawHTTPClient, defaultVerificationPolicy, logger)
		trustGroupMgr = peertrust.NewTrustGroupManager(cacheConfig, dirServiceClient, localIdentity.Scheme, logger, refreshTimeout)

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
			GlobalEnforce: cfg.PeerTrust.Policy.GlobalEnforce,
			AllowList:     cfg.PeerTrust.Policy.AllowList,
			DenyList:      cfg.PeerTrust.Policy.DenyList,
			ExemptList:    cfg.PeerTrust.Policy.ExemptList,
		}
		policyEngine = peertrust.NewPolicyEngine(policyCfg, trustGroupMgr, logger)
		logger.Info(
			"peer trust enabled",
			"config_paths", len(cfg.PeerTrust.ConfigPaths),
			"global_enforce", policyCfg.GlobalEnforce,
		)
		if runtimeEval.Trust.Status == policy.TrustStatusFailOpen {
			logger.Warn(
				"peer trust is enabled without global enforcement",
				"trust_status", runtimeEval.Trust.Status,
				"compatibility_scope", runtimeEval.CompatibilityScope,
			)
		}
	}

	var signer *crypto.RFC9421Signer
	if keyManager != nil {
		signer = crypto.NewRFC9421Signer(keyManager)
	}

	var outboundPolicy *outboundsigning.OutboundPolicy
	if !opts.SkipCrypto {
		outboundPolicy = outboundsigning.NewOutboundPolicy(
			outboundsigning.ResolveInputs(runtimePolicy, openCloudMeshPolicy),
			peerContract,
		)
	}

	var signatureMiddleware *signature.SignatureMiddleware
	if !opts.SkipSignatureMiddleware {
		peerDiscoveryAdapter := discovery.NewPeerDiscoveryAdapter(discoveryClient)
		peerDiscoveryAdapter.SetPeerContract(peerContract)
		signatureMiddleware = signature.NewSignatureMiddleware(
			runtimePolicy,
			peerContract,
			peerDiscoveryAdapter,
			localIdentity.Origin,
			logger,
		)
	}

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
		OpenCloudMeshPolicy: openCloudMeshPolicy,
		RuntimePolicy:       runtimePolicy,
		KeyManager:          keyManager,
		Signer:              signer,
		OutboundPolicy:      outboundPolicy,
		SignatureMiddleware: signatureMiddleware,
		TrustGroupMgr:       trustGroupMgr,
		PolicyEngine:        policyEngine,
		PeerContract:        peerContract,
		LocalIdentity:       localIdentity,
		Config:              cfg,
		Cache:               cacheInstance,
		RealIP:              realIPExtractor,
	}

	return BuildResult{
		Deps:        built,
		RootCAPool:  rootCAPool,
		RuntimeEval: runtimeEval,
		Persistence: persistence,
	}, nil
}
