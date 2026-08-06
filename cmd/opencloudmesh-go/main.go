// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package main runs the OCM reference implementation server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/server"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"

	// Register cache drivers
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

var version = "dev"

func printVersion(showVersion bool, w io.Writer) (done bool, err error) {
	if !showVersion {
		return false, nil
	}

	_, err = fmt.Fprintln(w, version)

	return true, err
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

func run(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("opencloudmesh-go", flag.ContinueOnError)
	fs.SetOutput(stdout)
	fs.Usage = func() {}

	configPath := fs.String("config", "", "Path to TOML config file (optional)")
	modeFlag := fs.String("mode", "", "Preset bundle: strict or dev")
	listenAddr := fs.String("listen", "", "Listen address (overrides config)")
	publicOrigin := fs.String("public-origin", "", "Public origin (overrides config)")
	externalBasePath := fs.String("external-base-path", "", "External base path (overrides config)")
	adminUsername := fs.String("admin-username", "", "Bootstrap admin username (overrides config)")
	adminPassword := fs.String("admin-password", "", "Bootstrap admin password (overrides config)")
	loggingLevel := fs.String("logging-level", "", "Log level: trace, debug, info, warn, error (overrides config)")
	tokenExchangePath := fs.String("token-exchange-path", "", "Token exchange endpoint path relative to /ocm/ (overrides config)")
	showVersion := fs.Bool("version", false, "Print version and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		return 2
	}

	done, err := printVersion(*showVersion, stdout)
	if done {
		if err != nil {
			return 1
		}

		return 0
	}

	cfg, logger, err := loadConfigAndLogger(
		*configPath,
		*modeFlag,
		config.FlagOverrides{
			ListenAddr:        listenAddr,
			PublicOrigin:      publicOrigin,
			ExternalBasePath:  externalBasePath,
			AdminUsername:     adminUsername,
			AdminPassword:     adminPassword,
			LoggingLevel:      loggingLevel,
			TokenExchangePath: tokenExchangePath,
		},
	)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		return 1
	}

	slog.SetDefault(logger)
	logger.Info("effective configuration", "config", cfg.Redacted())

	if validateErr := service.ValidatePreBootstrap(cfg); validateErr != nil {
		logger.Error("pre-bootstrap startup validation failed", "error", validateErr)
		return 1
	}

	result, err := wiring.Build(cfg, logger, wiring.BuildOpts{})
	if err != nil {
		logger.Error("failed to bootstrap dependencies", "error", err)
		return 1
	}

	logRuntimePosture(logger, cfg.Mode)

	d := result.Deps
	if d == nil {
		logger.Error(wiring.ErrMsgNilDepsAfterBuild)
		return 1
	}

	if bootstrapErr := bootstrapAdmin(context.Background(), cfg, d, logger); bootstrapErr != nil {
		logger.Error("failed to bootstrap super admin", "error", bootstrapErr)
		return 1
	}

	services, err := wiring.BuildCoreServices(cfg, logger, d)
	if err != nil {
		logger.Error("failed to create services", "error", err)
		return 1
	}

	if err := service.ValidateBuiltServices(services); err != nil {
		logger.Error("built service validation failed", "error", err)
		return 1
	}

	if err := runServer(context.Background(), cfg, logger, result, services); err != nil {
		logger.Error("server error", "error", err)
		return 1
	}

	logger.Info("server stopped")

	return 0
}

func loadConfigAndLogger(configPath, modeFlag string, overrides config.FlagOverrides) (*config.Config, *slog.Logger, error) {
	bootstrapLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := config.Load(config.LoaderOptions{
		ConfigPath:    configPath,
		ModeFlag:      modeFlag,
		FlagOverrides: overrides,
		Logger:        bootstrapLogger,
	})
	if err != nil {
		return nil, bootstrapLogger, err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel(cfg.Logging.Level)}))

	return cfg, logger, nil
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "trace":
		return slog.LevelDebug - 4 // slog has no trace, use debug-4
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func logRuntimePosture(logger *slog.Logger, mode string) {
	if mode == "strict" {
		logger.Info("resolved runtime posture", "mode", mode)

		return
	}

	logger.Warn("resolved runtime posture is non-strict", "mode", mode)
}

func bootstrapAdmin(ctx context.Context, cfg *config.Config, deps *wiring.Deps, logger *slog.Logger) error {
	bootstrap := identity.NewBootstrap(deps.PartyRepo, deps.UserAuth, logger)

	bootstrapUsername := cfg.Server.BootstrapAdmin.Username
	if bootstrapUsername == "" {
		bootstrapUsername = "admin"
	}

	explicitPasswordSet := cfg.Server.BootstrapAdmin.Password != ""

	generatedPassword, err := bootstrap.EnsureSuperAdmin(
		ctx,
		bootstrapUsername,
		cfg.Server.BootstrapAdmin.Password,
		explicitPasswordSet,
	)
	if err != nil {
		return err
	}

	if generatedPassword != "" {
		//nolint:forbidigo // one-time bootstrap secret must go to stdout, not slog
		if _, err := fmt.Println("One-time super admin password (save now, not logged):", generatedPassword); err != nil {
			return fmt.Errorf("failed to print one-time super admin password: %w", err)
		}
	}

	return nil
}

func runServer(ctx context.Context, cfg *config.Config, logger *slog.Logger, result wiring.BuildResult, services map[string]service.Service) error {
	serverDeps, err := wiring.BuildServerDeps(cfg, logger, result.Deps)
	if err != nil {
		return fmt.Errorf("failed to build server deps: %w", err)
	}

	srv, err := server.New(cfg, logger, services, serverDeps)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	srv.SetRootCAPool(result.RootCAPool)

	serverCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	srvErr := make(chan error, 1)

	go func() { //nolint:contextcheck // startup: goroutine runs detached srv.Start() lifecycle with internal context; threading ctx would change the public Start signature
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
		}
	}()

	logger.Info("server started, press Ctrl+C to stop")

	select {
	case err := <-srvErr:
		return err
	case <-serverCtx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown error: %w", err)
	}

	if result.Persistence != nil {
		if err := result.Persistence.Close(); err != nil {
			logger.Warn("error closing persistence", "error", err)
		}
	}

	return nil
}
