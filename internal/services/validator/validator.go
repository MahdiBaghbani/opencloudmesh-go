// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package validator provides the federation validator HTTP service shell.
// Route mounts and handlers are added in later waves; startup only registers
// the inert service so validator mode can pass pre-bootstrap checks.
package validator

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/httpwrap"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// Config holds validator service configuration (service-local knobs only).
type Config struct {
	Ratelimit RatelimitConfig `mapstructure:"ratelimit"`
}

// RatelimitConfig holds the per-service rate limiting opt-in.
type RatelimitConfig struct {
	Profile string `mapstructure:"profile"`
}

// ApplyDefaults implements cfg.Setter.
func (c *Config) ApplyDefaults() {}

// Inputs holds dependencies for the validator service constructor.
type Inputs struct{}

// Service is the federation validator HTTP service shell.
type Service struct {
	router chi.Router
	conf   *Config
	log    *slog.Logger
}

// New creates the validator service from narrow injected inputs.
func New(_ Inputs, m map[string]any, log *slog.Logger) (service.Service, error) {
	log = logutil.NoopIfNil(log)

	var c Config

	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, fmt.Errorf("services: decode validator config: %w", err)
	}

	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "validator", "unused_keys", unused)
	}

	r := chi.NewRouter()

	return &Service{router: r, conf: &c, log: log}, nil
}

// Handler returns the service HTTP handler; implements service.Service.
func (s *Service) Handler() http.Handler {
	return httpwrap.ClearRawPath(s.router)
}

// Prefix returns the service URL prefix; implements service.Service.
func (s *Service) Prefix() string {
	return "validator"
}

// Close performs no cleanup for this service; implements service.Service.
func (s *Service) Close() error {
	return nil
}
