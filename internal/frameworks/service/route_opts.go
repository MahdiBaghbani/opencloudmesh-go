// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package service

import (
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// DefaultRouteOpts returns baseline route opts for tests and dev defaults.
func DefaultRouteOpts() RouteOpts {
	return RouteOpts{
		ExternalBasePath:    "",
		WayfEnabled:         false,
		InviteAcceptEnabled: false,
		InvitesEnabled:      true,
		TokenExchangePath:   "token",
	}
}

// RouteOptsFromConfig derives route aggregation inputs from runtime config.
func RouteOptsFromConfig(cfg *config.Config) RouteOpts {
	opts := DefaultRouteOpts()
	if cfg == nil {
		return opts
	}

	opts.ExternalBasePath = cfg.ExternalBasePath

	if uiCfg := cfg.BuildServiceConfig("ui"); uiCfg != nil {
		if wayf, ok := uiCfg["wayf"].(map[string]any); ok {
			if enabled, ok := wayf["enabled"].(bool); ok && enabled {
				opts.WayfEnabled = true
			}
		}

		if inviteAccept, ok := uiCfg["invite_accept"].(map[string]any); ok {
			if enabled, ok := inviteAccept["enabled"].(bool); ok && enabled {
				opts.InviteAcceptEnabled = true
			}
		}
	}

	tokenPath := resolveTokenExchangePath(cfg)
	opts.TokenExchangePath = tokenPath

	return opts
}

func resolveTokenExchangePath(cfg *config.Config) string {
	if ocmCfg := cfg.BuildServiceConfig("ocm"); ocmCfg != nil {
		if te, ok := ocmCfg["token_exchange"].(map[string]any); ok {
			if path, ok := te["path"].(string); ok && strings.TrimSpace(path) != "" {
				return path
			}
		}
	}

	if cfg.TokenExchange.Path != "" {
		return cfg.TokenExchange.Path
	}

	return "token"
}

func featureActive(cond FeatureCondition, opts RouteOpts) bool {
	switch cond {
	case FeatureNone:
		return true
	case FeatureWAYFEnabled:
		return opts.WayfEnabled
	case FeatureInviteAcceptEnabled:
		return opts.InviteAcceptEnabled
	default:
		return true
	}
}

func sessionAuthRequired(policy SessionPolicy, opts RouteOpts) bool {
	switch policy {
	case SessionPublic:
		return false
	case SessionProtected:
		return true
	case SessionPublicWhenWAYF:
		return !opts.WayfEnabled
	default:
		return true
	}
}
