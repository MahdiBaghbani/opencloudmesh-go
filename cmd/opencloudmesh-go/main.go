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
	"syscall"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/federation"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/httpclient"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/server"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services"

	// Register cache drivers
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/cache/loader"

	// Register services (triggers init() registration)
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/loader"
)

func main() {
	// Parse flags
	configPath := flag.String("config", "", "Path to TOML config file (optional)")
	modeFlag := flag.String("mode", "", "Operating mode: strict, interop, or dev (overrides config)")
	listenAddr := flag.String("listen", "", "Listen address (overrides config)")
	externalOrigin := flag.String("external-origin", "", "External origin (overrides config)")
	externalBasePath := flag.String("external-base-path", "", "External base path (overrides config)")
	ssrfMode := flag.String("ssrf-mode", "", "SSRF protection mode: strict or off (overrides config)")
	signatureInboundMode := flag.String("signature-inbound-mode", "", "Signature inbound mode: strict, lenient, or off (overrides config)")
	signatureOutboundMode := flag.String("signature-outbound-mode", "", "Signature outbound mode: strict, criteria-only, token-only, or off (overrides config)")
	signatureAdvertise := flag.String("signature-advertise-http-request-signatures", "", "Advertise http-request-signatures in discovery criteria: true or false (overrides config)")
	signaturePeerOverride := flag.String("signature-peer-profile-level-override", "", "Peer profile override level: all, non-strict, or off (overrides config)")
	tlsMode := flag.String("tls-mode", "", "TLS mode: off, static, selfsigned, or acme (overrides config)")
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
			ExternalOrigin:                externalOrigin,
			ExternalBasePath:              externalBasePath,
			SSRFMode:                      ssrfMode,
			SignatureInboundMode:          signatureInboundMode,
			SignatureOutboundMode:         signatureOutboundMode,
			SignatureAdvertiseHTTPReqSigs: signatureAdvertise,
			SignaturePeerProfileOverride:  signaturePeerOverride,
			TLSMode:                       tlsMode,
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

		keyManager = crypto.NewKeyManager(cfg.Signature.KeyPath, cfg.ExternalOrigin)
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

	// Create outbound HTTP client
	rawHTTPClient := httpclient.New(&cfg.OutboundHTTP)
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

	// Create federation manager and policy engine if enabled
	var federationMgr *federation.FederationManager
	var policyEngine *federation.PolicyEngine
	if cfg.Federation.Enabled {
		// Compute refresh timeout from outbound HTTP timeout
		refreshTimeout := time.Duration(cfg.OutboundHTTP.TimeoutMS) * time.Millisecond

		// Create cache config from TOML
		cacheConfig := federation.CacheConfig{
			TTL:      time.Duration(cfg.Federation.MembershipCache.TTLSeconds) * time.Second,
			MaxStale: time.Duration(cfg.Federation.MembershipCache.MaxStaleSeconds) * time.Second,
		}

		// Create DS client (uses the safe HTTP client)
		dsClient := federation.NewDirectoryServiceClient(rawHTTPClient)

		// Create federation manager
		federationMgr = federation.NewFederationManager(cacheConfig, dsClient, logger, refreshTimeout)

		// Load federation configs from paths (one K2 JSON per file)
		for _, configPath := range cfg.Federation.ConfigPaths {
			fedCfg, err := federation.LoadFederationConfig(configPath)
			if err != nil {
				logger.Warn("failed to load federation config", "path", configPath, "error", err)
				continue
			}
			federationMgr.AddFederation(fedCfg)
			logger.Info("loaded federation", "federation_id", fedCfg.FederationID, "enabled", fedCfg.Enabled)
		}

		// Create policy engine from config
		policyCfg := &federation.PolicyConfig{
			GlobalEnforce: cfg.Federation.Policy.GlobalEnforce,
			AllowList:     cfg.Federation.Policy.AllowList,
			DenyList:      cfg.Federation.Policy.DenyList,
			ExemptList:    cfg.Federation.Policy.ExemptList,
		}
		policyEngine = federation.NewPolicyEngine(policyCfg, federationMgr, logger)
		logger.Info("federation enabled", "config_paths", len(cfg.Federation.ConfigPaths), "global_enforce", policyCfg.GlobalEnforce)
	}

	// Create peer profile registry from config
	var profileRegistry *federation.ProfileRegistry
	if len(cfg.PeerProfiles.Mappings) > 0 || len(cfg.PeerProfiles.CustomProfiles) > 0 {
		// Convert config.PeerProfile to federation.Profile
		customProfiles := make(map[string]*federation.Profile)
		for name, p := range cfg.PeerProfiles.CustomProfiles {
			customProfiles[name] = &federation.Profile{
				Name:                  name,
				AllowUnsignedInbound:  p.AllowUnsignedInbound,
				AllowUnsignedOutbound: p.AllowUnsignedOutbound,
				AllowMismatchedHost:   p.AllowMismatchedHost,
				AllowHTTP:             p.AllowHTTP,
				TokenExchangeQuirks:   p.TokenExchangeQuirks,
			}
		}
		// Convert config.PeerProfileMapping to federation.ProfileMapping
		mappings := make([]federation.ProfileMapping, len(cfg.PeerProfiles.Mappings))
		for i, m := range cfg.PeerProfiles.Mappings {
			mappings[i] = federation.ProfileMapping{
				Pattern:     m.Pattern,
				ProfileName: m.Profile,
			}
		}
		profileRegistry = federation.NewProfileRegistry(customProfiles, mappings)
	} else {
		// Create registry with just builtin profiles
		profileRegistry = federation.NewProfileRegistry(nil, nil)
	}

	// Create signer for outbound requests (needed for SharedDeps)
	var signer *crypto.RFC9421Signer
	if keyManager != nil {
		signer = crypto.NewRFC9421Signer(keyManager)
	}

	// Create outbound signing policy (needed for SharedDeps)
	outboundPolicy := federation.NewOutboundPolicy(cfg, profileRegistry)

	// Create signature middleware (needed by OCM service for per-endpoint verification)
	peerDiscoveryAdapter := discovery.NewPeerDiscoveryAdapter(discoveryClient)
	signatureMiddleware := crypto.NewSignatureMiddleware(&cfg.Signature, peerDiscoveryAdapter, logger)

	// Create repos once for SharedDeps.
	incomingShareRepo := shares.NewMemoryIncomingShareRepo()
	outgoingShareRepo := shares.NewMemoryOutgoingShareRepo()
	outgoingInviteRepo := invites.NewMemoryOutgoingInviteRepo()
	incomingInviteRepo := invites.NewMemoryIncomingInviteRepo()
	tokenStore := token.NewMemoryTokenStore()

	// Set SharedDeps for registry-based services (wellknown, ocm, apiservice, etc.)
	services.SetDeps(&services.Deps{
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
		// Federation
		FederationMgr:   federationMgr,
		PolicyEngine:    policyEngine,
		ProfileRegistry: profileRegistry,
		// Config
		Config: cfg,
	})

	// Build service configs using config helpers (Reva-aligned)
	// The service constructors decode via svccfg.Decode + ApplyDefaults

	// Construct wellknown service from registry
	wellknownConfig := cfg.BuildWellknownServiceConfig()
	wellknownNew := service.Get("wellknown")
	if wellknownNew == nil {
		logger.Error("wellknown service not registered")
		os.Exit(1)
	}
	wellknownSvc, err := wellknownNew(wellknownConfig, logger)
	if err != nil {
		logger.Error("failed to create wellknown service", "error", fmt.Errorf("wellknown: %w", err))
		os.Exit(1)
	}

	// Construct OCM service from registry
	// Add provider_fqdn which is needed for invites handler
	providerFQDN := extractProviderFQDN(cfg.ExternalOrigin)
	ocmConfig := cfg.BuildOCMServiceConfig()
	ocmConfig["provider_fqdn"] = providerFQDN

	ocmNew := service.Get("ocm")
	if ocmNew == nil {
		logger.Error("ocm service not registered")
		os.Exit(1)
	}
	ocmSvc, err := ocmNew(ocmConfig, logger)
	if err != nil {
		logger.Error("failed to create ocm service", "error", fmt.Errorf("ocm: %w", err))
		os.Exit(1)
	}

	// Construct ocmaux service from registry
	ocmauxConfig := map[string]any{} // No config fields needed
	ocmauxNew := service.Get("ocmaux")
	if ocmauxNew == nil {
		logger.Error("ocmaux service not registered")
		os.Exit(1)
	}
	ocmauxSvc, err := ocmauxNew(ocmauxConfig, logger)
	if err != nil {
		logger.Error("failed to create ocmaux service", "error", fmt.Errorf("ocmaux: %w", err))
		os.Exit(1)
	}

	// Construct apiservice from registry
	apiserviceConfig := map[string]any{
		"provider_fqdn": providerFQDN,
	}
	apiserviceNew := service.Get("apiservice")
	if apiserviceNew == nil {
		logger.Error("apiservice not registered")
		os.Exit(1)
	}
	apiserviceSvc, err := apiserviceNew(apiserviceConfig, logger)
	if err != nil {
		logger.Error("failed to create apiservice", "error", fmt.Errorf("apiservice: %w", err))
		os.Exit(1)
	}

	// Construct uiservice from registry
	uiserviceConfig := map[string]any{
		"external_base_path": cfg.ExternalBasePath,
	}
	uiserviceNew := service.Get("uiservice")
	if uiserviceNew == nil {
		logger.Error("uiservice not registered")
		os.Exit(1)
	}
	uiserviceSvc, err := uiserviceNew(uiserviceConfig, logger)
	if err != nil {
		logger.Error("failed to create uiservice", "error", fmt.Errorf("uiservice: %w", err))
		os.Exit(1)
	}

	// Construct webdavservice from registry
	webdavserviceConfig := map[string]any{
		"webdav_token_exchange_mode": cfg.WebDAVTokenExchange.Mode,
	}
	webdavserviceNew := service.Get("webdavservice")
	if webdavserviceNew == nil {
		logger.Error("webdavservice not registered")
		os.Exit(1)
	}
	webdavserviceSvc, err := webdavserviceNew(webdavserviceConfig, logger)
	if err != nil {
		logger.Error("failed to create webdavservice", "error", fmt.Errorf("webdavservice: %w", err))
		os.Exit(1)
	}

	// Create and start server (all dependencies come from SharedDeps)
	srv, err := server.New(cfg, logger, wellknownSvc, ocmSvc, ocmauxSvc, apiserviceSvc, uiserviceSvc, webdavserviceSvc)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}

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

// extractProviderFQDN extracts the host:port from an external origin URL.
func extractProviderFQDN(externalOrigin string) string {
	// Remove scheme
	fqdn := externalOrigin
	if idx := len("https://"); len(fqdn) > idx && fqdn[:idx] == "https://" {
		fqdn = fqdn[idx:]
	} else if idx := len("http://"); len(fqdn) > idx && fqdn[:idx] == "http://" {
		fqdn = fqdn[idx:]
	}
	// Remove trailing slash
	if len(fqdn) > 0 && fqdn[len(fqdn)-1] == '/' {
		fqdn = fqdn[:len(fqdn)-1]
	}
	return fqdn
}
