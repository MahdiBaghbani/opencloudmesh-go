// Package main runs the OCM reference implementation server.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/app"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/server"

	// Register cache drivers
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"

	// Register interceptors (triggers init() registration)
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/loader"

	// Register services (triggers init() registration)
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/loader"
)

func main() {
	configPath := flag.String("config", "", "Path to TOML config file (optional)")
	modeFlag := flag.String("mode", "", "Preset bundle: strict, compat, or dev (legacy alias: interop)")
	listenAddr := flag.String("listen", "", "Listen address (overrides config)")
	publicOrigin := flag.String("public-origin", "", "Public origin (overrides config)")
	externalBasePath := flag.String("external-base-path", "", "External base path (overrides config)")
	compatibilityScope := flag.String("compatibility-scope", "", "Compatibility scope: none, scoped, or unbounded (overrides config)")
	signatureInboundMode := flag.String("signature-inbound-mode", "", "Signature inbound mode: strict, lenient, or off (overrides config)")
	signatureOutboundMode := flag.String("signature-outbound-mode", "", "Signature outbound mode: strict, criteria-only, token-only, or off (overrides config)")
	signaturePeerOverride := flag.String("signature-peer-profile-level-override", "", "Peer profile override level: all, non-strict, or off (overrides config)")
	adminUsername := flag.String("admin-username", "", "Bootstrap admin username (overrides config)")
	adminPassword := flag.String("admin-password", "", "Bootstrap admin password (overrides config)")
	loggingLevel := flag.String("logging-level", "", "Log level: trace, debug, info, warn, error (overrides config)")
	loggingAllowSensitive := flag.String("logging-allow-sensitive", "", "Allow sensitive values in logs: true or false (overrides config)")
	tokenExchangeEnabled := flag.String("token-exchange-enabled", "", "Enable token exchange: true or false (overrides config)")
	tokenExchangePath := flag.String("token-exchange-path", "", "Token exchange endpoint path relative to /ocm/ (overrides config)")
	requireTokenExchange := flag.String("require-token-exchange", "", "Require must-exchange-token for receive strictness: true or false (overrides config)")
	peerPolicy := flag.String("peer-policy", "", "Peer policy: legacy, prefer-strict, or strict (overrides config)")
	flag.Parse()

	bootstrapLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Config precedence: preset bundle -> TOML file -> CLI flags
	cfg, err := config.Load(config.LoaderOptions{
		ConfigPath: *configPath,
		ModeFlag:   *modeFlag,
		FlagOverrides: config.FlagOverrides{
			ListenAddr:                   listenAddr,
			PublicOrigin:                 publicOrigin,
			ExternalBasePath:             externalBasePath,
			CompatibilityScope:           compatibilityScope,
			SignatureInboundMode:         signatureInboundMode,
			SignatureOutboundMode:        signatureOutboundMode,
			SignaturePeerProfileOverride: signaturePeerOverride,
			AdminUsername:                adminUsername,
			AdminPassword:                adminPassword,
			LoggingLevel:                 loggingLevel,
			LoggingAllowSensitive:        loggingAllowSensitive,
			TokenExchangeEnabled:         tokenExchangeEnabled,
			TokenExchangePath:            tokenExchangePath,
			RequireTokenExchange:         requireTokenExchange,
			PeerPolicy:                   peerPolicy,
		},
		Logger: bootstrapLogger,
	})
	if err != nil {
		bootstrapLogger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

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
	logger.Info("effective configuration", "config", cfg.Redacted())

	// Unknown [http.services.*] keys fail fast before any side-effecting bootstrap
	// (directory creation, key generation) so a typo never causes partial startup.
	if cfg.HTTP.Services != nil {
		var names []string
		for name := range cfg.HTTP.Services {
			names = append(names, name)
		}
		if unknown, allowed := service.CheckServiceNames(names); len(unknown) > 0 {
			logger.Error("unknown service names in [http.services]",
				"unknown", strings.Join(unknown, ", "),
				"allowed", strings.Join(allowed, ", "),
			)
			os.Exit(1)
		}
	}

	result, err := app.BootstrapDeps(cfg, logger, app.WireOptions{})
	if err != nil {
		logger.Error("failed to bootstrap dependencies", "error", err)
		os.Exit(1)
	}

	// Posture guard: compatibility_scope=none requires a resolved strict posture.
	runtimeEval := result.RuntimeEval
	if cfg.CompatibilityScope == "none" && !runtimeEval.Strict.IsStrict {
		logger.Error(
			"compatibility_scope=none contradicts resolved runtime posture",
			"tier", runtimeEval.DerivedTier,
			"compatibility_scope", runtimeEval.CompatibilityScope,
			"reasons", runtimeEval.Strict.ViolationReasons,
		)
		os.Exit(1)
	}

	if runtimeEval.Strict.IsStrict {
		logger.Info(
			"resolved runtime posture",
			"tier", runtimeEval.DerivedTier,
			"compatibility_scope", runtimeEval.CompatibilityScope,
			"strict", runtimeEval.Strict.IsStrict,
			"trust_status", runtimeEval.Trust.Status,
		)
	} else {
		logger.Warn(
			"resolved runtime posture is non-strict",
			"tier", runtimeEval.DerivedTier,
			"compatibility_scope", runtimeEval.CompatibilityScope,
			"strict", runtimeEval.Strict.IsStrict,
			"reasons", runtimeEval.Strict.ViolationReasons,
			"trust_status", runtimeEval.Trust.Status,
		)
	}

	d := deps.GetDeps()
	if d == nil {
		logger.Error(app.ErrMsgNilDepsAfterBootstrap)
		os.Exit(1)
	}
	bootstrap := identity.NewBootstrap(d.PartyRepo, d.UserAuth, logger)
	bootstrapUsername := cfg.Server.BootstrapAdmin.Username
	if bootstrapUsername == "" {
		bootstrapUsername = "admin"
	}
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
			logger.Error("failed to create service", "service", name, "error", err)
			os.Exit(1)
		}
		services[name] = svc
	}

	srv, err := server.New(cfg, logger, services)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}
	srv.SetRootCAPool(result.RootCAPool)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srvErr := make(chan error, 1)
	go func() {
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
		}
	}()

	logger.Info("server started, press Ctrl+C to stop")

	select {
	case err := <-srvErr:
		logger.Error("server error", "error", err)
		os.Exit(1)
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", "error", err)
		os.Exit(1)
	}

	logger.Info("server stopped")
}
