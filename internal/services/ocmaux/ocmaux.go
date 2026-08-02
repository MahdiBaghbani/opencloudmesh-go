// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package ocmaux provides OCM auxiliary endpoints (WAYF helpers).
package ocmaux

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	ocmauxcomp "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocmaux"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/httpwrap"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// Config holds ocmaux service configuration.
type Config struct {
	Ratelimit RatelimitConfig `mapstructure:"ratelimit"`
}

// RatelimitConfig holds the per-service rate limiting opt-in.
type RatelimitConfig struct {
	Profile string `mapstructure:"profile"`
}

// ApplyDefaults implements cfg.Setter.
func (c *Config) ApplyDefaults() {}

// Service is the ocm-aux service.
type Service struct {
	router chi.Router
	conf   *Config
	log    *slog.Logger
}

// New creates a new ocm-aux service from narrow injected inputs.
func New(inputs Inputs, m map[string]any, log *slog.Logger) (service.Service, error) {
	log = logutil.NoopIfNil(log)

	if err := validateInputs(inputs); err != nil {
		return nil, err
	}

	var c Config

	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, err
	}

	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "ocmaux", "unused_keys", unused)
	}

	auxHandler := ocmauxcomp.NewAuxHandler(inputs.TrustGroupMgr, inputs.DiscoveryClient, log)

	var discoverMiddleware func(http.Handler) http.Handler

	if c.Ratelimit.Profile != "" {
		profileConfig, err := interceptors.GetProfileConfig(inputs.InterceptorProfiles, "ratelimit", c.Ratelimit.Profile)
		if err != nil {
			return nil, fmt.Errorf("ocmaux: %w", err)
		}

		discoverMiddleware, err = ratelimit.New(inputs.Ratelimit, profileConfig, log)
		if err != nil {
			return nil, fmt.Errorf("ocmaux: failed to create ratelimit interceptor: %w", err)
		}
	}

	r := chi.NewRouter()
	r.Get(RouteFederations, auxHandler.HandleFederations)

	if discoverMiddleware != nil {
		r.With(discoverMiddleware).Get(RouteDiscover, auxHandler.HandleDiscover)
	} else {
		r.Get(RouteDiscover, auxHandler.HandleDiscover)
	}

	return &Service{router: r, conf: &c, log: log}, nil
}

func validateInputs(in Inputs) error {
	if in.Ratelimit.KeyFunc == nil {
		return errors.New("ocmaux: Ratelimit.KeyFunc is required")
	}

	return nil
}

// Handler returns the service HTTP handler; implements service.Service.
func (s *Service) Handler() http.Handler {
	return httpwrap.ClearRawPath(s.router)
}

// Prefix returns the service URL prefix; implements service.Service.
func (s *Service) Prefix() string {
	return "ocm-aux"
}

// Close performs no cleanup for this service; implements service.Service.
func (s *Service) Close() error {
	return nil
}
