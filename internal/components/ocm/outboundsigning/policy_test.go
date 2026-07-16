// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outboundsigning_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/ocm"
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
		if kind == outboundsigning.EndpointTokenExchange || kind == outboundsigning.EndpointShares {
			if !decision.ShouldSign {
				t.Errorf("%s must be signed even when outbound_mode=off", kind)
			}
			if decision.Error != nil {
				t.Errorf("%s with signer should not error when outbound_mode=off", kind)
			}
			continue
		}
		if decision.ShouldSign {
			t.Errorf("outbound_mode=off should not sign %s", kind)
		}
		if decision.Error != nil {
			t.Errorf("outbound_mode=off should not error for %s", kind)
		}
	}
}

func TestOutboundPolicy_Off_TokenExchangeRequiresSigner(t *testing.T) {
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "off",
	}

	decision := policy.ShouldSign(outboundsigning.EndpointTokenExchange, "example.com", nil, false)
	if !decision.ShouldSign {
		t.Error("token exchange must require signing even when outbound_mode=off")
	}
	if decision.Error == nil {
		t.Error("token exchange without signer should error when outbound_mode=off")
	}
}

func TestOutboundPolicy_Off_SharesRequireSigner(t *testing.T) {
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "off",
	}

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "example.com", nil, false)
	if !decision.ShouldSign {
		t.Error("share dispatch must require signing even when outbound_mode=off")
	}
	if decision.Error == nil {
		t.Error("share dispatch without signer should error when outbound_mode=off")
	}
}

func TestOutboundPolicy_Strict_AlwaysSigns(t *testing.T) {
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "strict",
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
		OutboundMode: "token-only",
	}

	// Token exchange should sign
	decision := policy.ShouldSign(outboundsigning.EndpointTokenExchange, "example.com", nil, true)
	if !decision.ShouldSign {
		t.Error("token-only should sign token exchange")
	}

	// Shares must always sign
	decision = policy.ShouldSign(outboundsigning.EndpointShares, "example.com", nil, true)
	if !decision.ShouldSign {
		t.Error("token-only must still sign shares")
	}

	// Notifications should not sign
	decision = policy.ShouldSign(outboundsigning.EndpointNotifications, "example.com", nil, true)
	if decision.ShouldSign {
		t.Error("token-only should not sign notifications")
	}
}

func TestOutboundPolicy_CriteriaOnly_SignsWhenRequired(t *testing.T) {
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "criteria-only",
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
	if !decision.ShouldSign {
		t.Error("criteria-only must sign shares even when peer does not require signatures")
	}
}

func TestOutboundPolicy_CriteriaOnly_FailsWhenPeerLacksCapability(t *testing.T) {
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "criteria-only",
	}

	// Peer requires signatures but lacks http-sig capability.
	discBroken := &discovery.Discovery{
		Capabilities: []string{},
		Criteria:     []string{"http-request-signatures"},
	}

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "example.com", discBroken, true)
	if !decision.ShouldSign {
		t.Error("share dispatch must sign even when peer lacks http-sig capability")
	}
	if decision.Error != nil {
		t.Error("share dispatch should not error when signer is available")
	}
}

func TestOutboundPolicy_CriteriaOnly_SignsWithoutDiscoveryPublicKeys(t *testing.T) {
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "criteria-only",
	}

	disc := &discovery.Discovery{
		Capabilities: []string{"http-sig"},
		Criteria:     []string{"http-request-signatures"},
		PublicKeys:   []discovery.PublicKey{},
	}

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "example.com", disc, true)
	if !decision.ShouldSign {
		t.Fatalf("criteria-only should sign when peer requires signatures via JWKS path: %+v", decision)
	}
	if decision.Error != nil {
		t.Fatalf("empty discovery publicKeys must not block outbound signing: %v", decision.Error)
	}
}

func TestOutboundPolicy_CriteriaOnly_MissingDiscoveryRejectsByDefault(t *testing.T) {
	// Compat's preset OutboundMode is strict, so set criteria-only explicitly
	// here to exercise the criteria-only decision path this test targets.
	cfg := config.CompatConfig()
	cfg.Signature.OutboundMode = "criteria-only"
	contract := ocm.MustCompileContract(t, nil, nil)
	runtimePolicy := ocm.RuntimePolicy(t, cfg, contract)
	policy := ocm.OutboundPolicy(t, runtimePolicy, contract)

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "example.com", nil, true)
	if !decision.ShouldSign {
		t.Fatalf("criteria-only must sign shares even when discovery is unavailable: %+v", decision)
	}
	if decision.Error != nil {
		t.Fatalf("share dispatch with signer should not error when discovery is unavailable: %+v", decision)
	}

	decision = policy.ShouldSign(outboundsigning.EndpointNotifications, "example.com", nil, true)
	if !decision.ShouldSign {
		t.Fatalf("criteria-only should require signing when discovery is unavailable: %+v", decision)
	}
	if decision.Error == nil {
		t.Fatalf("expected error when discovery is unavailable: %+v", decision)
	}
}

func TestOutboundPolicy_CriteriaOnly_SharesAlwaysSignWithoutDiscovery(t *testing.T) {
	cfg := config.DevConfig()
	cfg.Signature.OutboundMode = "criteria-only"
	contract := ocm.MustCompileContract(t, nil, nil)
	runtimePolicy := ocm.RuntimePolicy(t, cfg, contract)
	policy := ocm.OutboundPolicy(t, runtimePolicy, contract)

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "example.com", nil, true)
	if !decision.ShouldSign {
		t.Fatalf("criteria-only must still sign shares when discovery is unavailable: %+v", decision)
	}
	if decision.Error != nil {
		t.Fatalf("criteria-only should not error for shares when discovery is unavailable: %+v", decision)
	}
}

func TestOutboundPolicy_CriteriaOnly_MissingDiscoveryAllowsMatchedPeerOverride(t *testing.T) {
	cfg := config.CompatConfig()
	cfg.Signature.OutboundMode = "criteria-only"
	contract := ocm.MustCompileContract(t,
		map[string]*peercompat.Profile{
			"compat": {
				Name:                   "compat",
				AllowUnsignedDiscovery: true,
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: "peer.example.com", Profile: "compat"},
		},
	)
	runtimePolicy := ocm.RuntimePolicy(t, cfg, contract)
	policy := ocm.OutboundPolicy(t, runtimePolicy, contract)

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "peer.example.com", nil, true)
	if !decision.ShouldSign {
		t.Fatalf("matched peer allow_unsigned_discovery must still sign shares: %+v", decision)
	}
	if decision.Error != nil {
		t.Fatalf("expected no error for matched peer share signing: %+v", decision)
	}
}

func TestOutboundPolicy_TokenExchange_PeerProfileQuirkStillSigns(t *testing.T) {
	profiles := map[string]*peercompat.Profile{
		"nextcloud": {
			Name:                "nextcloud",
			TokenExchangeQuirks: []string{"accept_plain_token"},
		},
	}
	mappings := []peercompat.ProfileMapping{
		{Pattern: "*.nextcloud.com", Profile: "nextcloud"},
	}
	contract := ocm.MustCompileContract(t, profiles, mappings)

	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "criteria-only",
		PeerContract: contract,
	}

	decision := policy.ShouldSign(outboundsigning.EndpointTokenExchange, "cloud.nextcloud.com", nil, true)
	if !decision.ShouldSign {
		t.Errorf("token exchange must stay signed even when accept_plain_token quirk exists: %+v", decision)
	}
}

func TestOutboundPolicy_Strict_AlwaysSignsRegardlessOfPeerProfile(t *testing.T) {
	profiles := map[string]*peercompat.Profile{
		"compat": {
			Name:                  "compat",
			AllowUnsignedOutbound: true,
		},
	}
	mappings := []peercompat.ProfileMapping{
		{Pattern: "compat.example.com", Profile: "compat"},
	}
	contract := ocm.MustCompileContract(t, profiles, mappings)

	discNoCriteria := &discovery.Discovery{
		Capabilities: []string{},
		Criteria:     []string{},
	}

	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "strict",
		PeerContract: contract,
	}

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "compat.example.com", discNoCriteria, true)
	if !decision.ShouldSign {
		t.Error("strict mode must sign even when peer profile allows unsigned outbound")
	}

	decision = policy.ShouldSign(outboundsigning.EndpointShares, "normal.example.com", discNoCriteria, true)
	if !decision.ShouldSign {
		t.Error("should sign for non-matched peer in strict mode")
	}
}

func TestOutboundPolicy_Strict_SignsWhenPeerRequiresHTTPSig(t *testing.T) {
	profiles := map[string]*peercompat.Profile{
		"compat": {
			Name:                  "compat",
			AllowUnsignedOutbound: true,
		},
	}
	mappings := []peercompat.ProfileMapping{
		{Pattern: "strict-peer.example.com", Profile: "compat"},
	}
	contract := ocm.MustCompileContract(t, profiles, mappings)

	discRequiresSigs := &discovery.Discovery{
		Capabilities: []string{"http-sig"},
		Criteria:     []string{"must-use-http-sig"},
	}

	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "strict",
		PeerContract: contract,
	}

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "strict-peer.example.com", discRequiresSigs, true)
	if !decision.ShouldSign {
		t.Error("strict mode must sign when peer requires must-use-http-sig")
	}
	if decision.Reason != "strict mode: always sign" {
		t.Errorf("unexpected reason: %s", decision.Reason)
	}

	discNoCriteria := &discovery.Discovery{
		Capabilities: []string{},
		Criteria:     []string{},
	}
	decision = policy.ShouldSign(outboundsigning.EndpointShares, "strict-peer.example.com", discNoCriteria, true)
	if !decision.ShouldSign {
		t.Error("strict mode must sign even when peer has no http-sig criteria")
	}
}

func TestOutboundPolicy_Strict_MissingDiscoveryDoesNotImplyUnsigned(t *testing.T) {
	profiles := map[string]*peercompat.Profile{
		"compat": {
			Name:                  "compat",
			AllowUnsignedOutbound: true,
		},
	}
	mappings := []peercompat.ProfileMapping{
		{Pattern: "compat.example.com", Profile: "compat"},
	}
	contract := ocm.MustCompileContract(t, profiles, mappings)

	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "strict",
		PeerContract: contract,
	}

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "compat.example.com", nil, true)
	if !decision.ShouldSign {
		t.Fatalf("missing discovery must not imply unsigned fallback in strict mode: %+v", decision)
	}
	if decision.Error != nil {
		t.Fatalf("unexpected error with signer available: %+v", decision)
	}
}

func TestOutboundPolicy_Strict_MissingDiscoveryStillSigns(t *testing.T) {
	profiles := map[string]*peercompat.Profile{
		"compat": {
			Name:                   "compat",
			AllowUnsignedOutbound:  true,
			AllowUnsignedDiscovery: true,
		},
	}
	mappings := []peercompat.ProfileMapping{
		{Pattern: "compat.example.com", Profile: "compat"},
	}
	contract := ocm.MustCompileContract(t, profiles, mappings)

	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "strict",
		PeerContract: contract,
	}

	decision := policy.ShouldSign(outboundsigning.EndpointShares, "compat.example.com", nil, true)
	if !decision.ShouldSign {
		t.Fatalf("strict mode must sign when discovery is unavailable: %+v", decision)
	}
	if decision.Error != nil {
		t.Fatalf("unexpected error with signer available: %+v", decision)
	}
}

func TestNewOutboundPolicy(t *testing.T) {
	cfg := &config.Config{
		Signature: config.SignatureConfig{
			OutboundMode:             "criteria-only",
			PeerProfileLevelOverride: "non-strict",
		},
	}

	contract := ocm.MustCompileContract(t, nil, nil)
	runtimePolicy := ocm.RuntimePolicy(t, cfg, contract)
	policy := ocm.OutboundPolicy(t, runtimePolicy, contract)

	if policy.OutboundMode != "criteria-only" {
		t.Errorf("expected outbound_mode=criteria-only, got %s", policy.OutboundMode)
	}
	if policy.StrictNone {
		t.Error("expected StrictNone=false for criteria-only with non-strict override")
	}
}

func TestNewOutboundPolicy_StrictNone(t *testing.T) {
	cfg := &config.Config{
		Signature: config.SignatureConfig{
			OutboundMode:             "strict",
			PeerProfileLevelOverride: "off",
		},
	}

	contract := ocm.MustCompileContract(t, nil, nil)
	runtimePolicy := ocm.RuntimePolicy(t, cfg, contract)
	policy := ocm.OutboundPolicy(t, runtimePolicy, contract)

	if !policy.StrictNone {
		t.Error("expected StrictNone=true for strict with peer_profile_level_override=off")
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
		{Pattern: "cloud.nextcloud.com", Profile: "nextcloud"},
	}
	cfg := config.DevConfig()
	contract := ocm.MustCompileContract(t, profiles, mappings)
	runtimePolicy := ocm.RuntimePolicy(t, cfg, contract)
	policy := ocm.OutboundPolicy(t, runtimePolicy, contract)

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

func TestOutboundPolicy_StrictNone_AllKindsSign(t *testing.T) {
	// strict + peer_profile_level_override=off is the compatibility_scope=none lane.
	// Every endpoint kind must sign when a signer is present.
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "strict",
		StrictNone:   true,
	}

	kinds := []outboundsigning.EndpointKind{
		outboundsigning.EndpointShares,
		outboundsigning.EndpointNotifications,
		outboundsigning.EndpointInvites,
		outboundsigning.EndpointTokenExchange,
	}

	for _, kind := range kinds {
		decision := policy.ShouldSign(kind, "example.com", nil, true)
		if !decision.ShouldSign {
			t.Errorf("strict-none should sign %s, got reason: %s", kind, decision.Reason)
		}
		if decision.Error != nil {
			t.Errorf("strict-none with signer should not error for %s: %v", kind, decision.Error)
		}
	}
}

func TestOutboundPolicy_StrictNone_NoSigner_Errors(t *testing.T) {
	// Without a signer every endpoint kind in strict+none must report ShouldSign=true
	// and a non-nil error.
	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "strict",
		StrictNone:   true,
	}

	kinds := []outboundsigning.EndpointKind{
		outboundsigning.EndpointShares,
		outboundsigning.EndpointNotifications,
		outboundsigning.EndpointInvites,
		outboundsigning.EndpointTokenExchange,
	}

	for _, kind := range kinds {
		decision := policy.ShouldSign(kind, "example.com", nil, false)
		if !decision.ShouldSign {
			t.Errorf("strict-none no-signer: ShouldSign must be true for %s", kind)
		}
		if decision.Error == nil {
			t.Errorf("strict-none no-signer: expected error for %s", kind)
		}
	}
}

func TestOutboundPolicy_StrictNone_TokenExchange_NoUnsignedFallback(t *testing.T) {
	// Even when the peer profile carries accept_plain_token quirk, strict+none
	// must sign token exchange and never fall back to unsigned.
	profiles := map[string]*peercompat.Profile{
		"nextcloud": {
			Name:                "nextcloud",
			TokenExchangeQuirks: []string{"accept_plain_token"},
		},
	}
	mappings := []peercompat.ProfileMapping{
		{Pattern: "cloud.nextcloud.com", Profile: "nextcloud"},
	}
	contract := ocm.MustCompileContract(t, profiles, mappings)

	policy := &outboundsigning.OutboundPolicy{
		OutboundMode: "strict",
		StrictNone:   true,
		PeerContract: contract,
	}

	// Signer present: must sign, no error.
	decision := policy.ShouldSign(outboundsigning.EndpointTokenExchange, "cloud.nextcloud.com", nil, true)
	if !decision.ShouldSign {
		t.Errorf("strict-none must sign token exchange even with accept_plain_token quirk: %+v", decision)
	}
	if decision.Error != nil {
		t.Errorf("strict-none with signer should not error: %v", decision.Error)
	}

	// No signer: must signal error, not fall back to unsigned.
	decision = policy.ShouldSign(outboundsigning.EndpointTokenExchange, "cloud.nextcloud.com", nil, false)
	if !decision.ShouldSign {
		t.Errorf("strict-none no-signer token exchange: ShouldSign must be true: %+v", decision)
	}
	if decision.Error == nil {
		t.Errorf("strict-none no-signer token exchange: expected error, got unsigned fallback: %+v", decision)
	}
}

func TestOutboundPolicy_TokenExchange_StrictPolicyRequiresSigning(t *testing.T) {
	cfg := config.DevConfig()
	cfg.PeerPolicy = "strict"
	enabled := true
	cfg.TokenExchange.Enabled = &enabled
	contract := ocm.MustCompileContract(t, nil, nil)
	runtimePolicy := ocm.RuntimePolicy(t, cfg, contract)
	policy := ocm.OutboundPolicy(t, runtimePolicy, contract)

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
