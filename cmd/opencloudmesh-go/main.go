// Package main is the entrypoint for the opencloudmesh-go server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/instanceid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/directoryservice"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	invitesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/inbox"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/server"
	tlspkg "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/tls"

	// Register cache drivers
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"

	// Register interceptors (triggers init() registration)
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/loader"

	// Register services (triggers init() registration)
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/loader"
)

func main() {
	// Parse flags
	configPath := flag.String("config", "", "Path to TOML config file (optional)")
	modeFlag := flag.String("mode", "", "Operating mode: strict, interop, or dev (overrides config)")
	listenAddr := flag.String("listen", "", "Listen address (overrides config)")
	publicOrigin := flag.String("public-origin", "", "Public origin (overrides config)")
	externalBasePath := flag.String("external-base-path", "", "External base path (overrides config)")
	ssrfMode := flag.String("ssrf-mode", "", "SSRF protection mode: strict or off (overrides config)")
	signatureInboundMode := flag.String("signature-inbound-mode", "", "Signature inbound mode: strict, lenient, or off (overrides config)")
	signatureOutboundMode := flag.String("signature-outbound-mode", "", "Signature outbound mode: strict, criteria-only, token-only, or off (overrides config)")
	signatureAdvertise := flag.String("signature-advertise-http-request-signatures", "", "Advertise http-request-signatures in discovery criteria: true or false (overrides config)")
	signaturePeerOverride := flag.String("signature-peer-profile-level-override", "", "Peer profile override level: all, non-strict, or off (overrides config)")
	adminUsername := flag.String("admin-username", "", "Bootstrap admin username (overrides config)")
	adminPassword := flag.String("admin-password", "", "Bootstrap admin password (overrides config)")
	loggingLevel := flag.String("logging-level", "", "Log level: trace, debug, info, warn, error (overrides config)")
	loggingAllowSensitive := flag.String("logging-allow-sensitive", "", "Allow sensitive values in logs: true or false (overrides config)")
	tokenExchangeEnabled := flag.String("token-exchange-enabled", "", "Enable token exchange: true or false (overrides config)")
	tokenExchangePath := flag.String("token-exchange-path", "", "Token exchange endpoint path relative to /ocm/ (overrides config)")
	webdavTokenExchangeMode := flag.String("webdav-token-exchange-mode", "", "WebDAV token exchange enforcement mode: strict, lenient, or off (overrides config)")
	flag.Parse()

	// Bootstrap logger for config loading errors (uses default level)
	bootstrapLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Load config with precedence: mode preset -> TOML file -> CLI flags
	cfg, err := config.Load(config.LoaderOptions{
		ConfigPath: *configPath,
		ModeFlag:   *modeFlag,
		FlagOverrides: config.FlagOverrides{
			ListenAddr:                    listenAddr,
			PublicOrigin:                  publicOrigin,
			ExternalBasePath:              externalBasePath,
			SSRFMode:                      ssrfMode,
			SignatureInboundMode:          signatureInboundMode,
			SignatureOutboundMode:         signatureOutboundMode,
			SignatureAdvertiseHTTPReqSigs: signatureAdvertise,
			SignaturePeerProfileOverride:  signaturePeerOverride,
			AdminUsername:                 adminUsername,
			AdminPassword:                 adminPassword,
			LoggingLevel:                  loggingLevel,
			LoggingAllowSensitive:         loggingAllowSensitive,
			TokenExchangeEnabled:          tokenExchangeEnabled,
			TokenExchangePath:             tokenExchangePath,
			WebDAVTokenExchangeMode:       webdavTokenExchangeMode,
		},
		Logger: bootstrapLogger,
	})
	if err != nil {
		bootstrapLogger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Create logger with configured level
	var level slog.Level
	switch cfg.Logging.Level {
	case "trace":
		level = slog.LevelDebug - 4 // slog has no trace, use debug-4
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	// Log effective config with secrets redacted
	logger.Info("effective configuration", "config", cfg.Redacted())

	// Create identity components
	partyRepo := identity.NewMemoryPartyRepo()
	sessionRepo := identity.NewMemorySessionRepo()
	userAuth := identity.NewUserAuth(3) // argon2id time parameter

	// Initialize key manager for HTTP signatures (5A rule)
	// Keys exist when inbound_mode != off OR outbound_mode != off
	var keyManager *crypto.KeyManager
	needsKeys := cfg.Signature.InboundMode != "off" || cfg.Signature.OutboundMode != "off"
	if needsKeys {
		// Ensure key directory exists
		keyDir := filepath.Dir(cfg.Signature.KeyPath)
		if keyDir != "" && keyDir != "." {
			if err := os.MkdirAll(keyDir, 0700); err != nil {
				logger.Error("failed to create key directory", "path", keyDir, "error", err)
				os.Exit(1)
			}
		}

		keyManager = crypto.NewKeyManager(cfg.Signature.KeyPath, cfg.PublicOrigin)
		if err := keyManager.LoadOrGenerate(); err != nil {
			logger.Error("failed to initialize signing key", "error", err)
			os.Exit(1)
		}
		logger.Info("initialized signing key", "keyId", keyManager.GetKeyID())
	}

	// Bootstrap super admin user
	bootstrap := identity.NewBootstrap(partyRepo, userAuth, logger)
	bootstrapUsername := cfg.Server.BootstrapAdmin.Username
	if bootstrapUsername == "" {
		bootstrapUsername = "admin"
	}
	// Determine if password was explicitly set (non-empty in config or via flag)
	explicitPasswordSet := cfg.Server.BootstrapAdmin.Password != ""
	if err := bootstrap.EnsureSuperAdmin(
		context.Background(),
		bootstrapUsername,
		cfg.Server.BootstrapAdmin.Password,
		explicitPasswordSet,
	); err != nil {
		logger.Error("failed to bootstrap super admin", "error", err)
		os.Exit(1)
	}

	// Build root CA pool from optional file/dir; nil means use system defaults
	rootCAPool, err := tlspkg.BuildRootCAPool(cfg.OutboundHTTP.TLSRootCAFile, cfg.OutboundHTTP.TLSRootCADir)
	if err != nil {
		logger.Error("failed to build root CA pool", "error", err)
		os.Exit(1)
	}

	// Create outbound HTTP client
	rawHTTPClient := httpclient.New(&cfg.OutboundHTTP, rootCAPool)
	httpClient := httpclient.NewContextClient(rawHTTPClient)

	// Create cache (defaults to in-memory if not configured)
	// Passes driver-specific config from [cache.drivers.<driver>] section
	cacheDriver := cfg.Cache.Driver
	if cacheDriver == "" {
		cacheDriver = "memory"
	}
	cacheInstance, err := cache.NewFromConfig(cacheDriver, cfg.Cache.Drivers)
	if err != nil {
		logger.Error("failed to create cache", "error", err)
		os.Exit(1)
	}

	// Create discovery client (mandatory for /ocm-aux/discover and share sending)
	discoveryClient := discovery.NewClient(rawHTTPClient, cacheInstance)

	// Create trust group manager and policy engine if enabled
	var trustGroupMgr *peertrust.TrustGroupManager
	var policyEngine *peertrust.PolicyEngine
	if cfg.PeerTrust.Enabled {
		// Compute refresh timeout from outbound HTTP timeout
		refreshTimeout := time.Duration(cfg.OutboundHTTP.TimeoutMS) * time.Millisecond

		// Create cache config from TOML
		cacheConfig := peertrust.CacheConfig{
			TTL:      time.Duration(cfg.PeerTrust.MembershipCache.TTLSeconds) * time.Second,
			MaxStale: time.Duration(cfg.PeerTrust.MembershipCache.MaxStaleSeconds) * time.Second,
		}

		// Compute default directory service verification policy from mode.
		// Strict mode requires verified signatures; interop/dev mode accepts unsigned.
		dsMode, _ := config.ParseMode(cfg.Mode)
		defaultVerificationPolicy := "required"
		if dsMode == config.ModeInterop || dsMode == config.ModeDev {
			defaultVerificationPolicy = "optional"
		}

		// Create directory service client (uses the safe HTTP client)
		dirServiceClient := directoryservice.NewClient(rawHTTPClient, defaultVerificationPolicy, logger)

		// Create trust group manager
		trustGroupMgr = peertrust.NewTrustGroupManager(cacheConfig, dirServiceClient, cfg.PublicScheme(), logger, refreshTimeout)

		// Load trust group configs from paths (one K2 JSON per file)
		for _, configPath := range cfg.PeerTrust.ConfigPaths {
			tgCfg, err := peertrust.LoadTrustGroupConfig(configPath)
			if err != nil {
				logger.Warn("failed to load trust group config", "path", configPath, "error", err)
				continue
			}
			trustGroupMgr.AddTrustGroup(tgCfg)
			logger.Info("loaded trust group", "trust_group_id", tgCfg.TrustGroupID, "enabled", tgCfg.Enabled)
		}

		// Create policy engine from config
		policyCfg := &peertrust.PolicyConfig{
			GlobalEnforce: cfg.PeerTrust.Policy.GlobalEnforce,
			AllowList:     cfg.PeerTrust.Policy.AllowList,
			DenyList:      cfg.PeerTrust.Policy.DenyList,
			ExemptList:    cfg.PeerTrust.Policy.ExemptList,
		}
		policyEngine = peertrust.NewPolicyEngine(policyCfg, trustGroupMgr, logger)
		logger.Info("peer trust enabled", "config_paths", len(cfg.PeerTrust.ConfigPaths), "global_enforce", policyCfg.GlobalEnforce)
	}

	// Create peer profile registry from config
	var profileRegistry *peercompat.ProfileRegistry
	if len(cfg.PeerProfiles.Mappings) > 0 || len(cfg.PeerProfiles.CustomProfiles) > 0 {
		// Convert config.PeerProfile to peercompat.Profile
		customProfiles := make(map[string]*peercompat.Profile)
		for name, p := range cfg.PeerProfiles.CustomProfiles {
			customProfiles[name] = &peercompat.Profile{
				Name:                     name,
				AllowUnsignedInbound:     p.AllowUnsignedInbound,
				AllowUnsignedOutbound:    p.AllowUnsignedOutbound,
				AllowMismatchedHost:      p.AllowMismatchedHost,
				AllowHTTP:                p.AllowHTTP,
				TokenExchangeQuirks:      p.TokenExchangeQuirks,
				RelaxMustExchangeToken:   p.RelaxMustExchangeToken,
				AllowedBasicAuthPatterns: p.AllowedBasicAuthPatterns,
			}
		}
		// Convert config.PeerProfileMapping to peercompat.ProfileMapping
		mappings := make([]peercompat.ProfileMapping, len(cfg.PeerProfiles.Mappings))
		for i, m := range cfg.PeerProfiles.Mappings {
			mappings[i] = peercompat.ProfileMapping{
				Pattern:     m.Pattern,
				ProfileName: m.Profile,
			}
		}
		profileRegistry = peercompat.NewProfileRegistry(customProfiles, mappings)
	} else {
		// Create registry with just builtin profiles
		profileRegistry = peercompat.NewProfileRegistry(nil, nil)
	}

	// Create signer for outbound requests (needed for SharedDeps)
	var signer *crypto.RFC9421Signer
	if keyManager != nil {
		signer = crypto.NewRFC9421Signer(keyManager)
	}

	// Create outbound signing policy (needed for SharedDeps)
	outboundPolicy := outboundsigning.NewOutboundPolicy(cfg, profileRegistry)

	// Create signature middleware (needed by OCM service for per-endpoint verification)
	peerDiscoveryAdapter := discovery.NewPeerDiscoveryAdapter(discoveryClient)
	signatureMiddleware := crypto.NewSignatureMiddleware(&cfg.Signature, peerDiscoveryAdapter, cfg.PublicOrigin, logger)

	// Create repos once for SharedDeps.
	incomingShareRepo := sharesinbox.NewMemoryIncomingShareRepo()
	outgoingShareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	outgoingInviteRepo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	incomingInviteRepo := invitesinbox.NewMemoryIncomingInviteRepo()
	tokenStore := token.NewMemoryTokenStore()

	// Create RealIP extractor for trusted-proxy-aware client identity
	realIPExtractor := realip.NewTrustedProxies(cfg.Server.TrustedProxies)

	// Derive local provider identity from PublicOrigin once at startup
	localProviderFQDN, err := instanceid.ProviderFQDN(cfg.PublicOrigin)
	if err != nil {
		logger.Error("failed to derive provider FQDN", "error", err)
		os.Exit(1)
	}
	localProviderFQDNForCompare, err := hostport.Normalize(localProviderFQDN, cfg.PublicScheme())
	if err != nil {
		logger.Error("failed to normalize provider FQDN for comparison", "error", err)
		os.Exit(1)
	}

	// Set SharedDeps for registry-based services (wellknown, ocm, api, ui, webdav, etc.)
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
		// Crypto
		KeyManager:          keyManager,
		Signer:              signer,
		OutboundPolicy:      outboundPolicy,
		SignatureMiddleware: signatureMiddleware,
		// Peer trust
		TrustGroupMgr:   trustGroupMgr,
		PolicyEngine:    policyEngine,
		ProfileRegistry: profileRegistry,
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

	// Validate that all [http.services.*] keys in TOML refer to known services.
	// Unknown keys fail fast so typos don't silently disable functionality.
	if cfg.HTTP.Services != nil {
		allowed := service.RegisteredServices()
		allowedSet := make(map[string]struct{}, len(allowed))
		for _, name := range allowed {
			allowedSet[name] = struct{}{}
		}

		var unknown []string
		for name := range cfg.HTTP.Services {
			if _, ok := allowedSet[name]; !ok {
				unknown = append(unknown, name)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			sort.Strings(allowed)
			logger.Error("unknown service names in [http.services]",
				"unknown", strings.Join(unknown, ", "),
				"allowed", strings.Join(allowed, ", "),
			)
			os.Exit(1)
		}
	}

	// Construct all core services via registry loop.
	// Each service derives cross-cutting values from SharedDeps internally.
	services := make(map[string]service.Service)
	for _, name := range service.CoreServices {
		svcCfg := cfg.BuildServiceConfig(name)
		if svcCfg == nil {
			svcCfg = make(map[string]any)
		}
		newFn := service.Get(name)
		if newFn == nil {
			logger.Error("core service not registered", "service", name)
			os.Exit(1)
		}
		svc, err := newFn(svcCfg, logger)
		if err != nil {
			logger.Error("failed to create service", "service", name, "error", fmt.Errorf("%s: %w", name, err))
			os.Exit(1)
		}
		services[name] = svc
	}

	srv, err := server.New(cfg, logger, services)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}
	srv.SetRootCAPool(rootCAPool)

	// Setup graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := srv.Start(); err != nil {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	logger.Info("server started, press Ctrl+C to stop")

	// Wait for shutdown signal
	<-ctx.Done()
	logger.Info("shutdown signal received")

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*1000000000) // 30 seconds
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", "error", err)
		os.Exit(1)
	}

	logger.Info("server stopped")
}

