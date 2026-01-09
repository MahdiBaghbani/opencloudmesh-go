// Package main is the entrypoint for the opencloudmesh-go server.
package main

import (
	"context"
	"flag"
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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/httpclient"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/server"

	// Register cache drivers
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/cache/loader"
)

func main() {
	// Parse flags
	configPath := flag.String("config", "", "Path to TOML config file (optional)")
	modeFlag := flag.String("mode", "", "Operating mode: strict, interop, or dev (overrides config)")
	listenAddr := flag.String("listen", "", "Listen address (overrides config)")
	externalOrigin := flag.String("external-origin", "", "External origin (overrides config)")
	externalBasePath := flag.String("external-base-path", "", "External base path (overrides config)")
	ssrfMode := flag.String("ssrf-mode", "", "SSRF protection mode: strict or off (overrides config)")
	signaturePolicy := flag.String("signature-policy", "", "Signature policy: strict, lenient, or off (overrides config)")
	tlsMode := flag.String("tls-mode", "", "TLS mode: off, static, selfsigned, or acme (overrides config)")
	adminUsername := flag.String("admin-username", "", "Bootstrap admin username (overrides config)")
	adminPassword := flag.String("admin-password", "", "Bootstrap admin password (overrides config)")
	flag.Parse()

	// Setup logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load config with precedence: mode preset -> TOML file -> CLI flags
	cfg, err := config.Load(config.LoaderOptions{
		ConfigPath: *configPath,
		ModeFlag:   *modeFlag,
		FlagOverrides: config.FlagOverrides{
			ListenAddr:       listenAddr,
			ExternalOrigin:   externalOrigin,
			ExternalBasePath: externalBasePath,
			SSRFMode:         ssrfMode,
			SignaturePolicy:  signaturePolicy,
			TLSMode:          tlsMode,
			AdminUsername:    adminUsername,
			AdminPassword:    adminPassword,
		},
	})
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Log effective config with secrets redacted
	logger.Info("effective configuration", "config", cfg.Redacted())

	// Create identity components
	partyRepo := identity.NewMemoryPartyRepo()
	sessionRepo := identity.NewMemorySessionRepo()
	userAuth := identity.NewUserAuth(3) // argon2id time parameter

	// Initialize key manager for HTTP signatures
	var keyManager *crypto.KeyManager
	if cfg.Signature.Mode != "off" {
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

	// Create federation manager if enabled
	var federationMgr *federation.FederationManager
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
	}

	// Create server dependencies
	deps := &server.Deps{
		PartyRepo:       partyRepo,
		SessionRepo:     sessionRepo,
		UserAuth:        userAuth,
		KeyManager:      keyManager,
		HTTPClient:      httpClient,
		DiscoveryClient: discoveryClient,
		FederationMgr:   federationMgr,
	}

	// Create and start server
	srv, err := server.New(cfg, logger, deps)
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
