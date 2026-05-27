package policy_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestRuntimePolicyStrictIncomingSharePayloadValidation(t *testing.T) {
	tests := []struct {
		name          string
		inboundMode   string
		authenticated bool
		want          bool
	}{
		{
			name:          "strict always validates strictly",
			inboundMode:   "strict",
			authenticated: false,
			want:          true,
		},
		{
			name:          "strict stays strict for authenticated peers",
			inboundMode:   "strict",
			authenticated: true,
			want:          true,
		},
		{
			name:          "lenient keeps unauthenticated peers non-strict",
			inboundMode:   "lenient",
			authenticated: false,
			want:          false,
		},
		{
			name:          "lenient validates authenticated peers strictly",
			inboundMode:   "lenient",
			authenticated: true,
			want:          true,
		},
		{
			name:          "off keeps non-strict path",
			inboundMode:   "off",
			authenticated: true,
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.DevConfig()
			cfg.Signature.InboundMode = tt.inboundMode

			got := policy.NewRuntimePolicy(cfg, nil).StrictIncomingSharePayloadValidation(tt.authenticated)
			if got != tt.want {
				t.Fatalf("StrictIncomingSharePayloadValidation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRuntimePolicyEvaluate_DerivesHTTPRequestSignatureRequirement(t *testing.T) {
	tests := []struct {
		name        string
		inboundMode string
		want        bool
	}{
		{
			name:        "strict requires HTTP request signatures",
			inboundMode: "strict",
			want:        true,
		},
		{
			name:        "lenient does not require HTTP request signatures",
			inboundMode: "lenient",
			want:        false,
		},
		{
			name:        "off does not require HTTP request signatures",
			inboundMode: "off",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.DevConfig()
			cfg.Signature.InboundMode = tt.inboundMode

			got := policy.NewRuntimePolicy(cfg, nil).Evaluate().Signature.RequiresHTTPRequestSignatures
			if got != tt.want {
				t.Fatalf("Signature.RequiresHTTPRequestSignatures = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRuntimePolicyEvaluate_DerivesStrictTier(t *testing.T) {
	cfg := config.StrictConfig()
	cfg.PeerPolicy = "strict"
	cfg.Signature.PeerProfileLevelOverride = "off"
	cfg.PeerTrust.Enabled = true
	cfg.PeerTrust.Policy.GlobalEnforce = true

	eval := policy.NewRuntimePolicy(cfg, nil).Evaluate()

	if eval.DerivedTier != policy.RuntimeTierStrict {
		t.Fatalf("expected strict tier, got %q", eval.DerivedTier)
	}
	if !eval.Strict.IsStrict {
		t.Fatalf("expected strict assessment true, reasons=%v", eval.Strict.ViolationReasons)
	}
	if eval.CompatibilityScope != "none" {
		t.Fatalf("expected compatibility scope none, got %q", eval.CompatibilityScope)
	}
	if eval.Trust.Status != policy.TrustStatusEnforced {
		t.Fatalf("expected trust status enforced, got %q", eval.Trust.Status)
	}
}

func TestRuntimePolicyEvaluate_DefaultStrictPresetClaimsStrict(t *testing.T) {
	cfg := config.StrictConfig()
	cfg.PeerTrust.Enabled = true
	cfg.PeerTrust.Policy.GlobalEnforce = true

	eval := policy.NewRuntimePolicy(cfg, nil).Evaluate()

	if eval.DerivedTier != policy.RuntimeTierStrict {
		t.Fatalf("expected strict tier for default strict preset, got %q", eval.DerivedTier)
	}
	if !eval.Strict.IsStrict {
		t.Fatalf("expected default strict preset to be strict, reasons=%v", eval.Strict.ViolationReasons)
	}
	if eval.CompatibilityScope != "none" {
		t.Fatalf("expected compatibility scope none, got %q", eval.CompatibilityScope)
	}
}

func TestRuntimePolicyEvaluate_DerivesCompatTier(t *testing.T) {
	cfg := config.CompatConfig()

	eval := policy.NewRuntimePolicy(cfg, nil).Evaluate()

	if eval.DerivedTier != policy.RuntimeTierCompat {
		t.Fatalf("expected compat tier, got %q", eval.DerivedTier)
	}
	if eval.Strict.IsStrict {
		t.Fatalf("expected non-strict assessment, got reasons=%v", eval.Strict.ViolationReasons)
	}
	if !hasReason(eval.Strict.ViolationReasons, "signature_inbound_mode_not_strict") {
		t.Fatalf("expected inbound-mode strict reason, got %v", eval.Strict.ViolationReasons)
	}
	if !hasReason(eval.Strict.ViolationReasons, "signature_outbound_mode_not_strict") {
		t.Fatalf("expected outbound-mode strict reason, got %v", eval.Strict.ViolationReasons)
	}
	if eval.CompatibilityScope != "unbounded" {
		t.Fatalf("expected unbounded compatibility scope, got %q", eval.CompatibilityScope)
	}
}

func TestRuntimePolicyEvaluate_DerivesDevTier(t *testing.T) {
	cfg := config.DevConfig()

	eval := policy.NewRuntimePolicy(cfg, nil).Evaluate()

	if eval.DerivedTier != policy.RuntimeTierDev {
		t.Fatalf("expected dev tier, got %q", eval.DerivedTier)
	}
	if eval.CompatibilityScope != "unbounded" {
		t.Fatalf("expected unbounded scope, got %q", eval.CompatibilityScope)
	}
}

func TestRuntimePolicyEvaluate_DevPresetCanResolveStrictPosture(t *testing.T) {
	cfg := config.DevConfig()
	cfg.CompatibilityScope = "none"
	cfg.RequireTokenExchange = true
	cfg.PeerPolicy = "strict"
	cfg.Signature.InboundMode = "strict"
	cfg.Signature.OutboundMode = "strict"
	cfg.Signature.PeerProfileLevelOverride = "off"
	cfg.Signature.OnDiscoveryError = "reject"
	cfg.Signature.AllowMismatch = false
	cfg.TLS.Mode = "selfsigned"
	cfg.OutboundHTTP.SSRF.Mode = "strict"
	cfg.OutboundHTTP.InsecureSkipVerify = false

	eval := policy.NewRuntimePolicy(cfg, nil).Evaluate()

	if eval.DerivedTier != policy.RuntimeTierStrict {
		t.Fatalf("expected strict tier after posture overrides, got %q", eval.DerivedTier)
	}
	if !eval.Strict.IsStrict {
		t.Fatalf("expected strict assessment true, reasons=%v", eval.Strict.ViolationReasons)
	}
	if eval.CompatibilityScope != "none" {
		t.Fatalf("expected compatibility scope none, got %q", eval.CompatibilityScope)
	}
}

func TestRuntimePolicy_DirectoryServiceVerificationPolicy(t *testing.T) {
	t.Run("strict posture keeps verification required", func(t *testing.T) {
		cfg := config.StrictConfig()
		cfg.PeerPolicy = "strict"
		cfg.Signature.PeerProfileLevelOverride = "off"

		runtimePolicy := policy.NewRuntimePolicy(cfg, nil)
		if runtimePolicy.AllowsGlobalCompatibilityDefaults() {
			t.Fatal("expected strict posture to keep global compatibility defaults disabled")
		}
		if got := runtimePolicy.DirectoryServiceVerificationPolicy(); got != "required" {
			t.Fatalf("expected required verification, got %q", got)
		}
	})

	t.Run("unbounded compatibility makes verification optional", func(t *testing.T) {
		cfg := config.CompatConfig()

		runtimePolicy := policy.NewRuntimePolicy(cfg, nil)
		if !runtimePolicy.AllowsGlobalCompatibilityDefaults() {
			t.Fatal("expected compat posture to allow global compatibility defaults")
		}
		if got := runtimePolicy.DirectoryServiceVerificationPolicy(); got != "optional" {
			t.Fatalf("expected optional verification, got %q", got)
		}
	})
}

func TestRuntimePolicyEvaluate_ReportsTrustAxis(t *testing.T) {
	t.Run("feature-off", func(t *testing.T) {
		cfg := config.StrictConfig()
		cfg.Signature.PeerProfileLevelOverride = "off"
		cfg.PeerTrust.Enabled = false

		eval := policy.NewRuntimePolicy(cfg, nil).Evaluate()
		if eval.Trust.Status != policy.TrustStatusFeatureOff {
			t.Fatalf("expected feature-off, got %q", eval.Trust.Status)
		}
	})

	t.Run("fail-open", func(t *testing.T) {
		cfg := config.StrictConfig()
		cfg.Signature.PeerProfileLevelOverride = "off"
		cfg.PeerTrust.Enabled = true
		cfg.PeerTrust.Policy.GlobalEnforce = false

		eval := policy.NewRuntimePolicy(cfg, nil).Evaluate()
		if eval.Trust.Status != policy.TrustStatusFailOpen {
			t.Fatalf("expected fail-open, got %q", eval.Trust.Status)
		}
		if eval.Strict.IsStrict {
			t.Fatalf("expected non-strict when trust is fail-open")
		}
		if !hasReason(eval.Strict.ViolationReasons, "peer_trust_fail_open") {
			t.Fatalf("expected fail-open reason, got %v", eval.Strict.ViolationReasons)
		}
	})
}

func TestRuntimePolicyEvaluate_DetectsMappedProfileRelaxations(t *testing.T) {
	cfg := config.StrictConfig()
	cfg.CompatibilityScope = "scoped"
	cfg.Signature.PeerProfileLevelOverride = "non-strict"
	cfg.PeerProfiles.Mappings = []config.PeerProfileMapping{
		{Pattern: "*.nextcloud.example", Profile: "nextcloud"},
	}
	registry := peercompat.NewProfileRegistry(nil, []peercompat.ProfileMapping{
		{Pattern: "*.nextcloud.example", ProfileName: "nextcloud"},
	})
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}

	eval := policy.NewRuntimePolicy(cfg, contract).Evaluate()

	if !eval.HasLiveProfileRelaxations {
		t.Fatal("expected live profile relaxations to be detected")
	}
	if !hasReason(eval.Strict.ViolationReasons, "peer_profile_relaxations_active") {
		t.Fatalf("expected profile-relaxations reason, got %v", eval.Strict.ViolationReasons)
	}
	if eval.CompatibilityScope != "scoped" {
		t.Fatalf("expected scoped compatibility scope, got %q", eval.CompatibilityScope)
	}
}

func TestRuntimePolicyEvaluate_DetectsBasicAuthAllowlistRelaxation(t *testing.T) {
	cfg := config.StrictConfig()
	cfg.CompatibilityScope = "scoped"
	cfg.Signature.PeerProfileLevelOverride = "non-strict"
	cfg.PeerProfiles.Mappings = []config.PeerProfileMapping{
		{Pattern: "*.peer.example", Profile: "basicauth-compat"},
	}
	registry := peercompat.NewProfileRegistry(
		map[string]*peercompat.Profile{
			"basicauth-compat": {
				Name:                     "basicauth-compat",
				AllowedBasicAuthPatterns: []string{"token:"},
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: "*.peer.example", ProfileName: "basicauth-compat"},
		},
	)
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}

	eval := policy.NewRuntimePolicy(cfg, contract).Evaluate()

	if !eval.HasLiveProfileRelaxations {
		t.Fatal("expected basic-auth allowlist to be treated as live relaxation")
	}
	if !hasReason(eval.Strict.ViolationReasons, "peer_profile_relaxations_active") {
		t.Fatalf("expected profile-relaxations reason, got %v", eval.Strict.ViolationReasons)
	}
	if eval.CompatibilityScope != "scoped" {
		t.Fatalf("expected scoped compatibility scope, got %q", eval.CompatibilityScope)
	}
}

func TestRuntimePolicyEvaluate_DetectsGrantTypeRelaxation(t *testing.T) {
	cfg := config.StrictConfig()
	cfg.CompatibilityScope = "scoped"
	cfg.Signature.PeerProfileLevelOverride = "non-strict"
	cfg.PeerProfiles.Mappings = []config.PeerProfileMapping{
		{Pattern: "*.peer.example", Profile: "grant-compat"},
	}
	registry := peercompat.NewProfileRegistry(
		map[string]*peercompat.Profile{
			"grant-compat": {
				Name:                   "grant-compat",
				TokenExchangeGrantType: "ocm_share",
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: "*.peer.example", ProfileName: "grant-compat"},
		},
	)
	contract, err := peercompat.BuildCompiledContractFromRegistry(registry)
	if err != nil {
		t.Fatalf("BuildCompiledContractFromRegistry() unexpected error: %v", err)
	}

	eval := policy.NewRuntimePolicy(cfg, contract).Evaluate()

	if !eval.HasLiveProfileRelaxations {
		t.Fatal("expected non-default grant type to be treated as live relaxation")
	}
	if !hasReason(eval.Strict.ViolationReasons, "peer_profile_relaxations_active") {
		t.Fatalf("expected profile-relaxations reason, got %v", eval.Strict.ViolationReasons)
	}
	if eval.CompatibilityScope != "scoped" {
		t.Fatalf("expected scoped compatibility scope, got %q", eval.CompatibilityScope)
	}
}

// TestRuntimePolicyEvaluate_StrictRoutePolicyUnderNoneIsStrict confirms that
// strict SSRF mode with a named route policy and compatibility_scope=none does
// not get mislabeled as dev posture and remains in the strict tier.
func TestRuntimePolicyEvaluate_StrictRoutePolicyUnderNoneIsStrict(t *testing.T) {
	cfg := config.StrictConfig()
	cfg.PeerTrust.Enabled = true
	cfg.PeerTrust.Policy.GlobalEnforce = true
	cfg.Signature.PeerProfileLevelOverride = "off"
	cfg.OutboundHTTP.SSRF.RoutePolicy = "private"
	cfg.OutboundHTTP.SSRF.RoutePolicies = map[string]config.SSRFRoutePolicyConfig{
		"private": {AllowPrivateHostSuffixes: []string{".internal"}},
	}

	eval := policy.NewRuntimePolicy(cfg, nil).Evaluate()

	if eval.DerivedTier != policy.RuntimeTierStrict {
		t.Fatalf(
			"strict route policy under none mislabeled: got %q (reasons=%v)",
			eval.DerivedTier, eval.Strict.ViolationReasons,
		)
	}
	if !eval.Strict.IsStrict {
		t.Fatalf("expected strict assessment, got reasons=%v", eval.Strict.ViolationReasons)
	}
	if eval.Transport.SSRFRoutePolicy != "private" {
		t.Fatalf("expected SSRFRoutePolicy=private, got %q", eval.Transport.SSRFRoutePolicy)
	}
}

// TestRuntimePolicyEvaluate_StrictRoutePolicyUnderScopedIsCompatNotDev confirms
// that strict SSRF mode with a route policy under compatibility_scope=scoped
// resolves to compat (not dev) even though it cannot be fully strict.
func TestRuntimePolicyEvaluate_StrictRoutePolicyUnderScopedIsCompatNotDev(t *testing.T) {
	cfg := config.StrictConfig()
	cfg.CompatibilityScope = "scoped"
	cfg.OutboundHTTP.SSRF.RoutePolicy = "private"
	cfg.OutboundHTTP.SSRF.RoutePolicies = map[string]config.SSRFRoutePolicyConfig{
		"private": {AllowPrivateHostSuffixes: []string{".internal"}},
	}

	eval := policy.NewRuntimePolicy(cfg, nil).Evaluate()

	if eval.DerivedTier != policy.RuntimeTierCompat {
		t.Fatalf(
			"strict route policy under scoped should be compat, got %q (reasons=%v)",
			eval.DerivedTier, eval.Strict.ViolationReasons,
		)
	}
	if eval.Strict.IsStrict {
		t.Fatalf("expected non-strict due to scoped compatibility_scope")
	}
	if !hasReason(eval.Strict.ViolationReasons, "compatibility_scope_not_none") {
		t.Fatalf("expected compatibility_scope_not_none reason, got %v", eval.Strict.ViolationReasons)
	}
	if hasReason(eval.Strict.ViolationReasons, "outbound_http_ssrf_mode_not_strict") {
		t.Fatalf("strict SSRF mode with route policy should not add ssrf-not-strict reason")
	}
	if eval.Transport.SSRFRoutePolicy != "private" {
		t.Fatalf("expected SSRFRoutePolicy=private, got %q", eval.Transport.SSRFRoutePolicy)
	}
}

// TestRuntimePolicyEvaluate_SSRFOffUnderUnboundedIsDev confirms that
// outbound_http.ssrf.mode=off under unbounded scope demotes posture to dev tier.
func TestRuntimePolicyEvaluate_SSRFOffUnderUnboundedIsDev(t *testing.T) {
	cfg := config.DevConfig()

	eval := policy.NewRuntimePolicy(cfg, nil).Evaluate()

	if eval.DerivedTier != policy.RuntimeTierDev {
		t.Fatalf("SSRF off under unbounded should be dev tier, got %q", eval.DerivedTier)
	}
	if !hasReason(eval.Strict.ViolationReasons, "outbound_http_ssrf_mode_not_strict") {
		t.Fatalf("expected outbound_http_ssrf_mode_not_strict reason, got %v", eval.Strict.ViolationReasons)
	}
	if eval.CompatibilityScope != "unbounded" {
		t.Fatalf("expected unbounded scope, got %q", eval.CompatibilityScope)
	}
}

func hasReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

// TestRuntimePolicyEvaluate_LegacySSRFModeFallback verifies that when
// OutboundHTTP.SSRF.Mode is empty but the legacy SSRFMode shim is set,
// the posture derives SSRFMode from the shim so programmatic configs are
// classified consistently during the migration period.
func TestRuntimePolicyEvaluate_LegacySSRFModeFallback(t *testing.T) {
	cfg := config.DevConfig()
	cfg.OutboundHTTP.SSRF.Mode = ""      // nested mode empty
	cfg.OutboundHTTP.SSRFMode = "strict" // legacy shim only

	eval := policy.NewRuntimePolicy(cfg, nil).Evaluate()

	if eval.Transport.SSRFMode != "strict" {
		t.Fatalf("expected SSRFMode=strict via legacy fallback, got %q", eval.Transport.SSRFMode)
	}
}
