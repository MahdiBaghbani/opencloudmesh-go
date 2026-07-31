// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package service_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestRouteOptsFromConfig_DevDefaults(t *testing.T) {
	opts := service.RouteOptsFromConfig(nil)
	if opts.TokenExchangePath != "token" {
		t.Errorf("TokenExchangePath = %q, want token", opts.TokenExchangePath)
	}
}

func TestRouteOptsFromConfig_NonNilBranches(t *testing.T) {
	tests := []struct {
		name            string
		cfg             *config.Config
		want            service.RouteOpts
		assertAuthPaths func(t *testing.T, opts service.RouteOpts)
	}{
		{
			name: "external base path",
			cfg: &config.Config{
				ExternalBasePath: "/ocm",
			},
			want: service.RouteOpts{
				ExternalBasePath:    "/ocm",
				WayfEnabled:         false,
				InviteAcceptEnabled: false,
				InvitesEnabled:      true,
				TokenExchangePath:   "token",
			},
			assertAuthPaths: func(t *testing.T, opts service.RouteOpts) {
				t.Helper()

				if service.SessionAuthRequiredForPath("/ocm/api/healthz", opts) {
					t.Error("expected /ocm/api/healthz public with external base path")
				}
			},
		},
		{
			name: "WAYF enabled via ui service config",
			cfg: &config.Config{
				HTTP: config.HTTPConfig{
					Services: map[string]map[string]any{
						"ui": {
							"wayf": map[string]any{"enabled": true},
						},
					},
				},
			},
			want: service.RouteOpts{
				ExternalBasePath:    "",
				WayfEnabled:         true,
				InviteAcceptEnabled: false,
				InvitesEnabled:      true,
				TokenExchangePath:   "token",
			},
			assertAuthPaths: func(t *testing.T, opts service.RouteOpts) {
				t.Helper()

				if service.SessionAuthRequiredForPath("/ui/wayf", opts) {
					t.Error("expected /ui/wayf public when WAYF enabled")
				}
			},
		},
		{
			name: "invite accept enabled via ui service config",
			cfg: &config.Config{
				HTTP: config.HTTPConfig{
					Services: map[string]map[string]any{
						"ui": {
							"invite_accept": map[string]any{"enabled": true},
						},
					},
				},
			},
			want: service.RouteOpts{
				ExternalBasePath:    "",
				WayfEnabled:         false,
				InviteAcceptEnabled: true,
				InvitesEnabled:      true,
				TokenExchangePath:   "token",
			},
			assertAuthPaths: func(t *testing.T, opts service.RouteOpts) {
				t.Helper()

				if !service.SessionAuthRequiredForPath("/ui/accept-invite", opts) {
					t.Error("expected /ui/accept-invite protected when invite accept enabled")
				}
			},
		},
		{
			name: "ocm token path from service config takes precedence",
			cfg: &config.Config{
				HTTP: config.HTTPConfig{
					Services: map[string]map[string]any{
						"ocm": {
							"token_exchange": map[string]any{"path": "custom-token"},
						},
					},
				},
				TokenExchange: config.TokenExchangeConfig{Path: "fallback-token"},
			},
			want: service.RouteOpts{
				ExternalBasePath:    "",
				WayfEnabled:         false,
				InviteAcceptEnabled: false,
				InvitesEnabled:      true,
				TokenExchangePath:   "custom-token",
			},
		},
		{
			name: "token path falls back to top-level config",
			cfg: &config.Config{
				TokenExchange: config.TokenExchangeConfig{Path: "fallback-token"},
			},
			want: service.RouteOpts{
				ExternalBasePath:    "",
				WayfEnabled:         false,
				InviteAcceptEnabled: false,
				InvitesEnabled:      true,
				TokenExchangePath:   "fallback-token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := service.RouteOptsFromConfig(tt.cfg)
			if opts != tt.want {
				t.Errorf("RouteOptsFromConfig() = %+v, want %+v", opts, tt.want)
			}

			if tt.assertAuthPaths != nil {
				tt.assertAuthPaths(t, opts)
			}
		})
	}
}
