// Package main is the entrypoint for the opencloudmesh-go server.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/server"
)

func main() {
	// Parse flags
	listenAddr := flag.String("listen", "", "Listen address (overrides config)")
	externalOrigin := flag.String("external-origin", "", "External origin (overrides config)")
	externalBasePath := flag.String("external-base-path", "", "External base path (overrides config)")
	flag.Parse()

	// Setup logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load config (using defaults for now, config file loading in Phase 0d)
	cfg := config.DefaultConfig()

	// Apply flag overrides
	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	}
	if *externalOrigin != "" {
		cfg.ExternalOrigin = *externalOrigin
	}
	if *externalBasePath != "" {
		cfg.ExternalBasePath = *externalBasePath
	}

	// Create identity components
	partyRepo := identity.NewMemoryPartyRepo()
	sessionRepo := identity.NewMemorySessionRepo()
	userAuth := identity.NewUserAuth(10) // bcrypt cost 10

	// Bootstrap admin user
	bootstrap := identity.NewBootstrap(partyRepo, userAuth, logger)
	adminUser := identity.SeededUser{
		Username:    "admin",
		Password:    "admin", // Default password for development
		DisplayName: "Administrator",
		Role:        "admin",
	}
	if _, err := bootstrap.Run(context.Background(), adminUser, nil); err != nil {
		logger.Error("failed to bootstrap users", "error", err)
		os.Exit(1)
	}

	// Create server dependencies
	deps := &server.Deps{
		PartyRepo:   partyRepo,
		SessionRepo: sessionRepo,
		UserAuth:    userAuth,
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
