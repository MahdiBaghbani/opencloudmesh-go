// Package app provides shared dependency wiring for server startup.
// This is the single construction seam shared by cmd/opencloudmesh-go/main.go
// and tests/integration/harness/harness.go.
package app

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
	invitesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/inbox"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
	tlspkg "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/tls"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/instanceid"
)

// WireOptions controls which optional infrastructure BootstrapDeps builds.
// The zero value matches production wiring (main.go path): full crypto,
// peer trust from config, real argon2id cost, and discovery cache enabled.
type WireOptions struct {
	// FastAuth uses low-cost argon2id parameters. Set true for tests.
	FastAuth bool

	// SkipCrypto disables KeyManager, Signer, and OutboundPolicy construction.
	// No signing keys are loaded or generated.
	SkipCrypto bool

	// SkipPeerTrust disables TrustGroupManager and PolicyEngine construction
	// regardless of cfg.PeerTrust.Enabled.
	SkipPeerTrust bool

	// SkipSignatureMiddleware disables SignatureMiddleware construction.
	SkipSignatureMiddleware bool

	// OutboundOverride replaces cfg.OutboundHTTP when non-nil.
	// Use in tests to allow localhost connections (SSRF off, InsecureSkipVerify).
	OutboundOverride *config.OutboundHTTPConfig

	// SkipDiscoveryCache wires a no-op cache for the discovery client instead
	// of the shared in-memory cache. In tests this prevents cross-test
	// discovery entry leakage without triggering the client's nil-fallback path.
	SkipDiscoveryCache bool
}

// BootstrapResult holds values built by BootstrapDeps that callers need
// after the call (posture check and TLS setup in main.go).
type BootstrapResult struct {
	// RootCAPool is the built root CA pool (nil = use system TLS defaults).
	// Pass to srv.SetRootCAPool in main.go.
	RootCAPool *x509.CertPool

	// RuntimeEval is the pre-computed runtime posture snapshot.
	// main.go uses this for the posture guard and startup logging.
	RuntimeEval policy.RuntimeEvaluation
}

// BootstrapDeps wires shared infrastructure and calls deps.SetDeps.
// Callers own: config loading, logger setup, admin bootstrapping,
// posture evaluation checks, and server lifecycle.
// Test callers must call deps.ResetDeps before this function.
// Returns an error immediately if deps are already set; use deps.ResetDeps
// to clear the singleton before a second call (tests only).
func BootstrapDeps(cfg *config.Config, logger *slog.Logger, opts WireOptions) (BootstrapResult, error) {
	if deps.GetDeps() != nil {
		return BootstrapResult{}, fmt.Errorf("BootstrapDeps called more than once without deps.ResetDeps")
	}

	peerContract, err := peercompat.NewCompiledContractFromConfig(cfg)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("compile peer compatibility contract: %w", err)
	}
	openCloudMeshPolicy := policy.NewOpenCloudMeshPolicy(cfg)
	runtimePolicy := policy.NewRuntimePolicy(cfg, peerContract)
	runtimeEval := runtimePolicy.Evaluate()

	partyRepo := identity.NewMemoryPartyRepo()
	sessionRepo := identity.NewMemorySessionRepo()
	var userAuth *identity.UserAuth
	if opts.FastAuth {
		userAuth = identity.NewUserAuthFast()
	} else {
		userAuth = identity.NewUserAuth(3) // argon2id time parameter
	}

	var keyManager *crypto.KeyManager
	if !opts.SkipCrypto {
		needsKeys := cfg.Signature.InboundMode != "off" || cfg.Signature.OutboundMode != "off"
		if needsKeys {
			keyDir := filepath.Dir(cfg.Signature.KeyPath)
			if keyDir != "" && keyDir != "." {
				if err := os.MkdirAll(keyDir, 0700); err != nil {
					return BootstrapResult{}, fmt.Errorf("create key directory %q: %w", keyDir, err)
				}
			}
			keyManager = crypto.NewKeyManager(cfg.Signature.KeyPath, cfg.PublicOrigin)
			if err := keyManager.LoadOrGenerate(); err != nil {
				return BootstrapResult{}, fmt.Errorf("initialize signing key: %w", err)
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
		return BootstrapResult{}, fmt.Errorf("build root CA pool: %w", err)
	}

	rawHTTPClient := httpclient.New(outboundCfg, rootCAPool)
	httpClient := httpclient.NewContextClient(rawHTTPClient)

	cacheDriver := cfg.Cache.Driver
	if cacheDriver == "" {
		cacheDriver = "memory"
	}
	cacheInstance, err := cache.NewFromConfig(cacheDriver, cfg.Cache.Drivers)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("create cache: %w", err)
	}

	// Pass an explicit no-op cache when SkipDiscoveryCache is set so that
	// discovery.NewClient never falls back to creating a shared in-memory
	// cache (its nil-fallback behaviour), preventing cross-test leakage.
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
		trustGroupMgr = peertrust.NewTrustGroupManager(cacheConfig, dirServiceClient, cfg.PublicScheme(), logger, refreshTimeout)

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

	var signatureMiddleware *crypto.SignatureMiddleware
	if !opts.SkipSignatureMiddleware {
		peerDiscoveryAdapter := discovery.NewPeerDiscoveryAdapter(discoveryClient)
		peerDiscoveryAdapter.SetPeerContract(peerContract)
		signatureMiddleware = crypto.NewSignatureMiddleware(
			runtimePolicy,
			peerContract,
			peerDiscoveryAdapter,
			cfg.PublicOrigin,
			logger,
		)
	}

	incomingShareRepo := sharesinbox.NewMemoryIncomingShareRepo()
	outgoingShareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	outgoingInviteRepo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	incomingInviteRepo := invitesinbox.NewMemoryIncomingInviteRepo()
	tokenStore := token.NewMemoryTokenStore()

	realIPExtractor := realip.NewTrustedProxies(cfg.Server.TrustedProxies)

	localProviderFQDN, err := instanceid.ProviderFQDN(cfg.PublicOrigin)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("derive provider FQDN: %w", err)
	}
	localProviderFQDNForCompare, err := hostport.Normalize(localProviderFQDN, cfg.PublicScheme())
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("normalize provider FQDN for comparison: %w", err)
	}

	deps.SetDeps(&deps.Deps{
		// Identity
		PartyRepo:   partyRepo,
		SessionRepo: sessionRepo,
		UserAuth:    userAuth,
		// Repos
		IncomingShareRepo:  incomingShareRepo,
		OutgoingShareRepo:  outgoingShareRepo,
		OutgoingInviteRepo: outgoingInviteRepo,
		IncomingInviteRepo: incomingInviteRepo,
		TokenStore:         tokenStore,
		// Clients
		HTTPClient:      httpClient,
		DiscoveryClient: discoveryClient,
		// Policy
		OpenCloudMeshPolicy: openCloudMeshPolicy,
		RuntimePolicy:       runtimePolicy,
		// Crypto
		KeyManager:          keyManager,
		Signer:              signer,
		OutboundPolicy:      outboundPolicy,
		SignatureMiddleware: signatureMiddleware,
		// Peer trust
		TrustGroupMgr: trustGroupMgr,
		PolicyEngine:  policyEngine,
		PeerContract:  peerContract,
		// Provider identity
		LocalProviderFQDN:           localProviderFQDN,
		LocalProviderFQDNForCompare: localProviderFQDNForCompare,
		// Config
		Config: cfg,
		// Cache (for interceptors like rate limiting)
		Cache: cacheInstance,
		// RealIP (for trusted-proxy-aware client identity)
		RealIP: realIPExtractor,
	})

	return BootstrapResult{
		RootCAPool:  rootCAPool,
		RuntimeEval: runtimeEval,
	}, nil
}
