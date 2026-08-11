// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peertrust"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func resolveInputs(cfg *config.Config, d *Deps) resolve.ResolveInputs {
	tokenPath := cfg.TokenExchange.Path
	resolver := policy.NewPeerMappingResolver(d.CodeFlow, &cfg.OCM.PeerMapping, cfg.OCM.CompatibilityScope)

	var advertiseDenylist, advertiseAllowlist bool

	if cfg.PeerTrust.Enabled {
		policyCfg := peertrustPolicyFromConfig(&cfg.PeerTrust.Policy)
		advertiseDenylist = policyCfg.HasDenylist()
		advertiseAllowlist = policyCfg.HasAllowlist()
	}

	return resolve.ResolveInputs{
		LocalIdentity:          d.LocalIdentity,
		RouteOpts:              service.RouteOptsFromConfig(cfg),
		TokenExchangePath:      tokenPath,
		KeyManager:             d.KeyManager,
		CodeFlow:               d.CodeFlow,
		Resolver:               resolver,
		JwksURIOverride:        cfg.Signature.JwksURI,
		AdvertiseDenylist:      advertiseDenylist,
		AdvertiseAllowlist:     advertiseAllowlist,
		AdvertiseMustInvite:    cfg.OCM.MustInviteEnforced(),
		AdvertiseNotifications: true,
	}
}

func peertrustPolicyFromConfig(cfg *config.PeerTrustPolicyConfig) *peertrust.PolicyConfig {
	if cfg == nil {
		return nil
	}

	return &peertrust.PolicyConfig{
		AllowList: cfg.AllowList,
		DenyList:  cfg.DenyList,
	}
}
