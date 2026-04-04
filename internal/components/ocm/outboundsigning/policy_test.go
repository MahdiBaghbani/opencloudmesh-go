// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outboundsigning_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	ocmpolicy "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestOutboundPolicy_Off(t *testing.T) {
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "off",
	}

	kinds := []outboundsigning.EndpointKind{
		outboundsigning.EndpointShares,
		outboundsigning.EndpointNotifications,
		outboundsigning.EndpointInvites,
		outboundsigning.EndpointTokenExchange,
	}

	for _, kind := range kinds {
		decision := policy.ShouldSign(kind, "example.com", nil, true)
		if decision.ShouldSign {
			t.Errorf("outbound_mode=off should not sign %s", kind)
		}
		if decision.Error != nil {
			t.Errorf("outbound_mode=off should not error for %s", kind)
		}
	}
}

func TestOutboundPolicy_Strict_AlwaysSigns(t *testing.T) {
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode:        "strict",
		PeerProfileOverride: "non-strict",
	}

	disc := &discovery.Discovery{
		Capabilities: []string{"http-sig"},
		Criteria:     []string{},
		PublicKeys:   []discovery.PublicKey{{KeyID: "key1"}},
	}

	kinds := []outboundsigning.EndpointKind{
		outboundsigning.EndpointShares,
		outboundsigning.EndpointNotifications,
		outboundsigning.EndpointInvites,
	}

	for _, kind := range kinds {
		decision := policy.ShouldSign(kind, "example.com", disc, true)
		if !decision.ShouldSign {
			t.Errorf("strict mode should sign %s", kind)
		}
		if decision.Error != nil {
			t.Errorf("strict mode with signer should not error for %s", kind)
		}
	}
}

func TestOutboundPolicy_Strict_NoSigner_Errors(t *testing.T) {
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "strict",
	}

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "example.com", nil, false)
	if !decision.ShouldSign {
		t.Error("strict mode should want to sign")
	}
	if decision.Error == nil {
		t.Error("strict mode without signer should error")
	}
}

func TestOutboundPolicy_TokenOnly_SignsTokenExchange(t *testing.T) {
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode:        "token-only",
		PeerProfileOverride: "non-strict",
	}

	// Token exchange should sign
	decision := policy.ShouldSign(outboundsigning.EndpointTokenExchange, "example.com", nil, true)
	if !decision.ShouldSign {
		t.Error("token-only should sign token exchange")
	}

	// Shares should not sign
	decision = policy.ShouldSign(outboundsigning.EndpointShares, "example.com", nil, true)
	if decision.ShouldSign {
		t.Error("token-only should not sign shares")
	}

	// Notifications should not sign
	decision = policy.ShouldSign(outboundsigning.EndpointNotifications, "example.com", nil, true)
	if decision.ShouldSign {
		t.Error("token-only should not sign notifications")
	}
}

func TestOutboundPolicy_CriteriaOnly_SignsWhenRequired(t *testing.T) {
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode:        "criteria-only",
		PeerProfileOverride: "non-strict",
	}

	// Peer requires signatures
	discRequires := &discovery.Discovery{
		Capabilities: []string{"http-sig"},
		Criteria:     []string{"http-request-signatures"},
		PublicKeys:   []discovery.PublicKey{{KeyID: "key1"}},
	}

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "example.com", discRequires, true)
	if !decision.ShouldSign {
		t.Error("criteria-only should sign when peer requires signatures")
	}

	// Peer does not require signatures
	discNoReq := &discovery.Discovery{
		Capabilities: []string{"http-sig"},
		Criteria:     []string{},
		PublicKeys:   []discovery.PublicKey{{KeyID: "key1"}},
	}

	decision = policy.ShouldSign(outboundsigning.EndpointShares, "example.com", discNoReq, true)
	if decision.ShouldSign {
		t.Error("criteria-only should not sign when peer does not require signatures")
	}
}

func TestOutboundPolicy_CriteriaOnly_FailsWhenPeerLacksCapability(t *testing.T) {
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode:        "criteria-only",
		PeerProfileOverride: "non-strict",
	}

	// Peer requires signatures but lacks capability
	discBroken := &discovery.Discovery{
		Capabilities: []string{}, // No http-sig
		Criteria:     []string{"http-request-signatures"},
		PublicKeys:   []discovery.PublicKey{}, // No keys
	}

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "example.com", discBroken, true)
	if decision.Error == nil {
		t.Error("criteria-only should error when peer requires signatures but lacks capability")
	}
}

func TestOutboundPolicy_CriteriaOnly_MissingDiscoveryRejectsByDefault(t *testing.T) {
	cfg := config.InteropConfig()
	registry := peercompat.NewProfileRegistry(nil, nil)
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}
	runtimePolicy := ocmpolicy.NewRuntimePolicy(cfg, contract)
	policy := outboundsigning.NewOutboundPolicy(runtimePolicy, registry, contract, nil)

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "example.com", nil, true)
	if !decision.ShouldSign {
		t.Fatalf("criteria-only with on_discovery_error=reject should require signing: %+v", decision)
	}
	if decision.Error == nil {
		t.Fatalf("expected error when discovery is unavailable in reject mode: %+v", decision)
	}
}

func TestOutboundPolicy_CriteriaOnly_MissingDiscoveryCanAllow(t *testing.T) {
	cfg := config.DevConfig()
	cfg.Signature.OutboundMode = "criteria-only"
	registry := peercompat.NewProfileRegistry(nil, nil)
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}
	runtimePolicy := ocmpolicy.NewRuntimePolicy(cfg, contract)
	policy := outboundsigning.NewOutboundPolicy(runtimePolicy, registry, contract, nil)

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "example.com", nil, true)
	if decision.ShouldSign {
		t.Fatalf("criteria-only with on_discovery_error=allow should not force signing: %+v", decision)
	}
	if decision.Error != nil {
		t.Fatalf("criteria-only with discovery allow should not error: %+v", decision)
	}
}

func TestOutboundPolicy_CriteriaOnly_MissingDiscoveryAllowsMatchedPeerOverride(t *testing.T) {
	cfg := config.InteropConfig()
	cfg.Signature.OutboundMode = "criteria-only"
	cfg.Signature.OnDiscoveryError = "reject"
	registry := peercompat.NewProfileRegistry(
		map[string]*peercompat.Profile{
			"compat": {
				Name:                   "compat",
				AllowUnsignedDiscovery: true,
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: "peer.example.com", ProfileName: "compat"},
		},
	)
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}
	runtimePolicy := ocmpolicy.NewRuntimePolicy(cfg, contract)
	policy := outboundsigning.NewOutboundPolicy(runtimePolicy, registry, contract, nil)

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "peer.example.com", nil, true)
	if decision.ShouldSign {
		t.Fatalf("matched peer allow_unsigned_discovery should allow missing discovery path: %+v", decision)
	}
	if decision.Error != nil {
		t.Fatalf("expected no error for matched peer discovery fail-open: %+v", decision)
	}
}

func TestOutboundPolicy_TokenExchange_PeerProfileQuirk(t *testing.T) {
	profiles := map[string]*peercompat.Profile{
		"nextcloud": {
			Name:                "nextcloud",
			TokenExchangeQuirks: []string{"accept_plain_token"},
		},
	}
	mappings := []peercompat.ProfileMapping{
		{Pattern: "*.nextcloud.com", ProfileName: "nextcloud"},
	}
	registry := peercompat.NewProfileRegistry(profiles, mappings)
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}

	// With non-strict override, quirk should apply
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode:        "criteria-only",
		PeerProfileOverride: "non-strict",
		PeerContract:        contract,
	}

	decision := policy.ShouldSign(outboundsigning.EndpointTokenExchange, "cloud.nextcloud.com", nil, true)
	if decision.ShouldSign {
		t.Error("should skip signing for peer with accept_plain_token quirk")
	}

	// With off override, quirk should not apply
	policyOff := &outboundsigning.OutboundPolicy{
		OutboundMode:        "criteria-only",
		PeerProfileOverride: "off",
		PeerContract:        contract,
	}

	decision = policyOff.ShouldSign(outboundsigning.EndpointTokenExchange, "cloud.nextcloud.com", nil, true)
	if !decision.ShouldSign {
		t.Error("should sign when peer_profile_level_override=off")
	}
}

func TestOutboundPolicy_Strict_PeerProfileOverrideAll(t *testing.T) {
	profiles := map[string]*peercompat.Profile{
		"compat": {
			Name:                  "compat",
			AllowUnsignedOutbound: true,
		},
	}
	mappings := []peercompat.ProfileMapping{
		{Pattern: "legacy.example.com", ProfileName: "compat"},
	}
	registry := peercompat.NewProfileRegistry(profiles, mappings)
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}

	// Discovery doc without criteria requirement
	discNoCriteria := &discovery.Discovery{
		Capabilities: []string{},
		Criteria:     []string{},
	}

	// With override=all, even strict mode can skip signing for matched peers
	// (when peer does not require signatures in their criteria)
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode:        "strict",
		PeerProfileOverride: "all",
		PeerContract:        contract,
	}

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "legacy.example.com", discNoCriteria, true)
	if decision.ShouldSign {
		t.Error("peer_profile_level_override=all should allow unsigned even in strict mode when peer has no criteria")
	}

	// For non-matched peer, should still sign
	decision = policy.ShouldSign(outboundsigning.EndpointShares, "normal.example.com", discNoCriteria, true)
	if !decision.ShouldSign {
		t.Error("should sign for non-matched peer in strict mode")
	}
}

func TestOutboundPolicy_Strict_CriteriaGuardrail(t *testing.T) {
	// Test the guardrail: AllowUnsignedOutbound must not override peer's criteria requirement
	profiles := map[string]*peercompat.Profile{
		"compat": {
			Name:                  "compat",
			AllowUnsignedOutbound: true,
		},
	}
	mappings := []peercompat.ProfileMapping{
		{Pattern: "strict-peer.example.com", ProfileName: "compat"},
	}
	registry := peercompat.NewProfileRegistry(profiles, mappings)
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}

	// Peer requires signatures via criteria
	discRequiresSigs := &discovery.Discovery{
		Capabilities: []string{"http-sig"},
		Criteria:     []string{"http-request-signatures"},
		PublicKeys:   []discovery.PublicKey{{KeyID: "key1"}},
	}

	policy := &outboundsigning.OutboundPolicy{
		OutboundMode:        "strict",
		PeerProfileOverride: "all",
		PeerContract:        contract,
	}

	// Even with override=all and AllowUnsignedOutbound=true, must sign because peer requires it
	decision := policy.ShouldSign(outboundsigning.EndpointShares, "strict-peer.example.com", discRequiresSigs, true)
	if !decision.ShouldSign {
		t.Error("must sign when peer criteria includes http-request-signatures, regardless of profile")
	}
	if decision.Reason != "peer requires signatures (criteria overrides profile relaxation)" {
		t.Errorf("unexpected reason: %s", decision.Reason)
	}

	// Peer without criteria requirement should allow unsigned
	discNoCriteria := &discovery.Discovery{
		Capabilities: []string{},
		Criteria:     []string{},
	}
	decision = policy.ShouldSign(outboundsigning.EndpointShares, "strict-peer.example.com", discNoCriteria, true)
	if decision.ShouldSign {
		t.Error("should skip signing when peer has no criteria and profile allows unsigned")
	}
}

func TestNewOutboundPolicy(t *testing.T) {
	cfg := &config.Config{
		Signature: config.SignatureConfig{
			OutboundMode:             "criteria-only",
			PeerProfileLevelOverride: "non-strict",
		},
	}

	registry := peercompat.NewProfileRegistry(nil, nil)
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}
	runtimePolicy := ocmpolicy.NewRuntimePolicy(cfg, contract)
	policy := outboundsigning.NewOutboundPolicy(runtimePolicy, registry, contract, nil)

	if policy.OutboundMode != "criteria-only" {
		t.Errorf("expected outbound_mode=criteria-only, got %s", policy.OutboundMode)
	}
	if policy.PeerProfileOverride != "non-strict" {
		t.Errorf("expected peer_profile_level_override=non-strict, got %s", policy.PeerProfileOverride)
	}
	if policy.OnDiscoveryError != "reject" {
		t.Errorf("expected on_discovery_error=reject default, got %s", policy.OnDiscoveryError)
	}
}

func TestOutboundPolicy_TokenExchange_StrictPeerIgnoresPlainTokenQuirk(t *testing.T) {
	profiles := map[string]*peercompat.Profile{
		"nextcloud": {
			Name:                "nextcloud",
			TokenExchangeQuirks: []string{"accept_plain_token"},
		},
	}
	mappings := []peercompat.ProfileMapping{
		{Pattern: "cloud.nextcloud.com", ProfileName: "nextcloud"},
	}
	registry := peercompat.NewProfileRegistry(profiles, mappings)
	cfg := config.DevConfig()
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}
	runtimePolicy := ocmpolicy.NewRuntimePolicy(cfg, contract)
	policy := outboundsigning.NewOutboundPolicy(runtimePolicy, registry, contract, ocmpolicy.NewOpenCloudMeshPolicy(cfg))

	disc := &discovery.Discovery{
		Capabilities: []string{"exchange-token"},
		Criteria:     []string{"token-exchange"},
	}
	decision := policy.ShouldSign(outboundsigning.EndpointTokenExchange, "cloud.nextcloud.com", disc, true)
	if !decision.ShouldSign {
		t.Fatalf("strict peer must require signed token exchange even when accept_plain_token quirk exists: %+v", decision)
	}
	if decision.Error != nil {
		t.Fatalf("unexpected error with signer available: %v", decision.Error)
	}
}

func TestOutboundPolicy_TokenExchange_StrictPolicyRequiresSigning(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PeerPolicy = "strict"
	enabled := true
	cfg.TokenExchange.Enabled = &enabled
	registry := peercompat.NewProfileRegistry(nil, nil)
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}
	runtimePolicy := ocmpolicy.NewRuntimePolicy(cfg, contract)
	policy := outboundsigning.NewOutboundPolicy(runtimePolicy, registry, contract, ocmpolicy.NewOpenCloudMeshPolicy(cfg))

	disc := &discovery.Discovery{
		Capabilities: []string{"exchange-token"},
		Criteria:     []string{},
	}
	decision := policy.ShouldSign(outboundsigning.EndpointTokenExchange, "peer.example.com", disc, false)
	if !decision.ShouldSign {
		t.Fatalf("strict policy should require signed token exchange: %+v", decision)
	}
	if decision.Error == nil {
		t.Fatal("expected error when signer is unavailable under strict policy")
	}
}
