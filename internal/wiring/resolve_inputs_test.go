// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// TestResolveInputs_CopiesSignatureJwksURI confirms cfg.Signature.JwksURI
// flows unchanged into resolve.ResolveInputs.JwksURIOverride, the same field
// resolve.Resolve threads into discovery.BuildParams.JwksURI.
func TestResolveInputs_CopiesSignatureJwksURI(t *testing.T) {
	cfg := config.DevConfig()
	cfg.Signature.JwksURI = "https://cloud.example.com/custom/jwks.json"

	d := &Deps{}

	in := resolveInputs(cfg, d)
	if in.JwksURIOverride != "https://cloud.example.com/custom/jwks.json" {
		t.Errorf("JwksURIOverride = %q, want configured override", in.JwksURIOverride)
	}
}

// TestResolveInputs_EmptySignatureJwksURILeavesOverrideEmpty confirms an
// unset override does not synthesize a value.
func TestResolveInputs_EmptySignatureJwksURILeavesOverrideEmpty(t *testing.T) {
	cfg := config.DevConfig()

	d := &Deps{}

	in := resolveInputs(cfg, d)
	if in.JwksURIOverride != "" {
		t.Errorf("JwksURIOverride = %q, want empty when signature.jwks_uri is unset", in.JwksURIOverride)
	}
}

func TestResolveInputs_AdvertisesPeerTrustListsWhenEnabled(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PeerTrust.Enabled = true
	cfg.PeerTrust.Policy.DenyList = []string{"blocked.example.com"}
	cfg.PeerTrust.Policy.AllowList = []string{"trusted.example.com"}

	in := resolveInputs(cfg, &Deps{})
	if !in.AdvertiseDenylist {
		t.Error("AdvertiseDenylist = false, want true for nonempty deny_list")
	}

	if !in.AdvertiseAllowlist {
		t.Error("AdvertiseAllowlist = false, want true for nonempty allow_list")
	}
}

func TestResolveInputs_OmitsPeerTrustListsWhenDisabled(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PeerTrust.Enabled = false
	cfg.PeerTrust.Policy.DenyList = []string{"blocked.example.com"}
	cfg.PeerTrust.Policy.AllowList = []string{"trusted.example.com"}

	in := resolveInputs(cfg, &Deps{})
	if in.AdvertiseDenylist {
		t.Error("AdvertiseDenylist = true, want false when peer_trust is disabled")
	}

	if in.AdvertiseAllowlist {
		t.Error("AdvertiseAllowlist = true, want false when peer_trust is disabled")
	}
}

func TestResolveInputs_OmitsEmptyPeerTrustLists(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PeerTrust.Enabled = true

	in := resolveInputs(cfg, &Deps{})
	if in.AdvertiseDenylist {
		t.Error("AdvertiseDenylist = true, want false for empty deny_list")
	}

	if in.AdvertiseAllowlist {
		t.Error("AdvertiseAllowlist = true, want false for empty allow_list")
	}
}

func TestResolveInputs_AdvertisesDenylistOnly(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PeerTrust.Enabled = true
	cfg.PeerTrust.Policy.DenyList = []string{"blocked.example.com"}

	in := resolveInputs(cfg, &Deps{})
	if !in.AdvertiseDenylist {
		t.Error("AdvertiseDenylist = false, want true for nonempty deny_list")
	}

	if in.AdvertiseAllowlist {
		t.Error("AdvertiseAllowlist = true, want false for empty allow_list")
	}
}

func TestResolveInputs_AdvertisesAllowlistOnly(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PeerTrust.Enabled = true
	cfg.PeerTrust.Policy.AllowList = []string{"trusted.example.com"}

	in := resolveInputs(cfg, &Deps{})
	if !in.AdvertiseAllowlist {
		t.Error("AdvertiseAllowlist = false, want true for nonempty allow_list")
	}

	if in.AdvertiseDenylist {
		t.Error("AdvertiseDenylist = true, want false for empty deny_list")
	}
}
