// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wellknown

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/httpwrap"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// Config holds wellknown service configuration.
type Config struct {
	OCMProvider resolve.ProviderConfig `mapstructure:"ocmprovider"`
}

// ApplyDefaults implements cfg.Setter.
func (c *Config) ApplyDefaults() {
	c.OCMProvider.ApplyDefaults()
}

type svc struct {
	router chi.Router
	conf   *Config
}

// New creates a new wellknown service from narrow injected inputs.
func New(inputs Inputs, m map[string]any, log *slog.Logger) (service.Service, error) {
	log = logutil.NoopIfNil(log)

	var c Config

	topLevel := make(map[string]any, len(m))
	for k, v := range m {
		if k != "ocmprovider" {
			topLevel[k] = v
		}
	}

	unused, err := svccfg.DecodeWithUnused(topLevel, &c)
	if err != nil {
		return nil, fmt.Errorf("services: decode service config: %w", err)
	}

	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "wellknown", "unused_keys", unused)
	}

	var rawOCMProvider map[string]any
	if om, ok := m["ocmprovider"].(map[string]any); ok {
		rawOCMProvider = om
		if err := svccfg.MustDecodeStrict(om, &c.OCMProvider); err != nil {
			return nil, fmt.Errorf("ocmprovider: %w", err)
		}
	} else if m["ocmprovider"] != nil {
		return nil, fmt.Errorf("ocmprovider must be a table")
	}

	r := chi.NewRouter()
	s := &svc{
		router: r,
		conf:   &c,
	}

	s.routerInit(inputs, rawOCMProvider, log)

	return s, nil
}

func discoveryHandler(
	handler *ocmHandler,
	signatureMiddleware *inboundsignature.SignatureMiddleware,
) http.Handler {
	if signatureMiddleware == nil {
		return handler
	}

	return signatureMiddleware.VerifyOCMRequestIfPresent()(handler)
}

func (s *svc) routerInit(inputs Inputs, rawOCMProvider map[string]any, log *slog.Logger) {
	handler := newOCMHandler(&s.conf.OCMProvider, rawOCMProvider, inputs.Resolve, log)

	ocm := discoveryHandler(handler, inputs.SignatureMiddleware)
	s.router.Get(RouteWellKnownOCM, ocm.ServeHTTP)
	s.router.Get(RouteWellKnownOCMSlash, ocm.ServeHTTP)
}

// Close implements service.Service.
func (s *svc) Close() error { return nil }

// Prefix implements service.Service.
func (s *svc) Prefix() string { return "" }

// Handler implements service.Service.
func (s *svc) Handler() http.Handler { return httpwrap.ClearRawPath(s.router) }
