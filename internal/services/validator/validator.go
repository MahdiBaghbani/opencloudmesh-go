// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validator

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseinvite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseshare"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/core"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/passive"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	svccfg "github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/cfg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service/httpwrap"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
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
type Inputs struct {
	Store               *validatorcore.Core
	FedCore             *core.Core
	DiscoveryClient     *discovery.Client
	Config              *config.Config
	Ratelimit           ratelimit.Inputs
	InterceptorProfiles map[string]map[string]any
	Log                 *slog.Logger

	// ReverseInvite is the prebuilt reverse-invite orchestration service. The
	// paste route mounts only when it is present; wiring builds it once and
	// shares the instance with the ocm invite-accepted decorator.
	ReverseInvite *reverseinvite.Service

	// ReverseShare is the prebuilt reverse-share leg. When present, its wait
	// opener wraps the session poll route so a session still in the
	// capability exercise re-enters the event-driven wait on a poll.
	ReverseShare *reverseshare.Service
}

// Service is the federation validator HTTP service shell.
type Service struct {
	router chi.Router
	conf   *Config
	log    *slog.Logger
}

// New creates the validator service from narrow injected inputs.
func New(inputs Inputs, m map[string]any, log *slog.Logger) (service.Service, error) {
	log = logutil.NoopIfNil(log)

	if err := validateInputs(inputs); err != nil {
		return nil, err
	}

	var c Config

	unused, err := svccfg.DecodeWithUnused(m, &c)
	if err != nil {
		return nil, fmt.Errorf("services: decode validator config: %w", err)
	}

	if len(unused) > 0 {
		log.Warn("unused config keys", "service", "validator", "unused_keys", unused)
	}

	r := chi.NewRouter()

	if inputs.Store != nil {
		if inputs.FedCore != nil {
			inputs.Store.SetStatsHostHasher(inputs.FedCore)
		}

		passiveHandler := passive.NewHandlerWithDiscovery(inputs.Store, inputs.DiscoveryClient, log)
		if inputs.Config != nil {
			passiveHandler.SetExternalBasePath(inputs.Config.ExternalBasePath)
		}

		var reverseWaitOpen passive.ReverseWaitOpener
		if inputs.ReverseShare != nil {
			reverseWaitOpen = inputs.ReverseShare.OpenReverseShareWait
		}

		startRatelimit, ratelimitErr := buildStartRatelimit(inputs, c.Ratelimit.Profile)
		if ratelimitErr != nil {
			return nil, ratelimitErr
		}

		var reverseHandler http.HandlerFunc
		if inputs.ReverseInvite != nil {
			reverseHandler = inputs.ReverseInvite.HandleReverseInvite
		} else {
			// The paste route stays unmounted and unadvertised; make the gap
			// observable instead of silently dropping the route.
			log.Warn("validator: reverse-invite service not wired, paste route disabled")
		}

		mountValidatorRoutes(r, passiveHandler, startRatelimit, reverseHandler, reverseWaitOpen)

		if reverseHandler != nil {
			markReverseInviteRouteMounted()
		}
	}

	return &Service{router: r, conf: &c, log: log}, nil
}

func validateInputs(in Inputs) error {
	if in.Ratelimit.KeyFunc == nil {
		return errors.New("validator: Ratelimit.KeyFunc is required")
	}

	return nil
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
