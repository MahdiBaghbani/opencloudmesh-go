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
			cfg.Signature.AdvertiseHTTPRequestSignatures = !tt.want

			got := policy.NewRuntimePolicy(cfg, nil).Evaluate().Signature.RequiresHTTPRequestSignatures
			if got != tt.want {
				t.Fatalf("Signature.RequiresHTTPRequestSignatures = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRuntimePolicyEvaluate_DerivesStrictTier(t *testing.T) {
	cfg := config.StrictConfig()
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

func TestRuntimePolicyEvaluate_DerivesCompatTier(t *testing.T) {
	cfg := config.InteropConfig()

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
}

func TestRuntimePolicyEvaluate_DerivesDevTier(t *testing.T) {
	cfg := config.DevConfig()

	eval := policy.NewRuntimePolicy(cfg, nil).Evaluate()

	if eval.DerivedTier != policy.RuntimeTierDev {
		t.Fatalf("expected dev tier, got %q", eval.DerivedTier)
	}
	if eval.CompatibilityScope != "dev-mode" {
		t.Fatalf("expected dev-mode scope, got %q", eval.CompatibilityScope)
	}
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
	cfg.Signature.PeerProfileLevelOverride = "non-strict"
	cfg.PeerProfiles.Mappings = []config.PeerProfileMapping{
		{Pattern: "*.nextcloud.example", Profile: "nextcloud"},
	}
	registry := peercompat.NewProfileRegistry(nil, []peercompat.ProfileMapping{
		{Pattern: "*.nextcloud.example", ProfileName: "nextcloud"},
	})

	eval := policy.NewRuntimePolicy(cfg, registry).Evaluate()

	if !eval.HasLiveProfileRelaxations {
		t.Fatal("expected live profile relaxations to be detected")
	}
	if !hasReason(eval.Strict.ViolationReasons, "peer_profile_relaxations_active") {
		t.Fatalf("expected profile-relaxations reason, got %v", eval.Strict.ViolationReasons)
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
