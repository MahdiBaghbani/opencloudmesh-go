package policy_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestCompatCompiler_EmitDiscoveryCriteriaUsesSpecConstants(t *testing.T) {
	falseVal := false
	compiler := policy.NewCompatCompiler(
		&policy.CodeFlow{RequiresHTTPRequestSignatures: &falseVal},
		nil,
		config.CompatibilityScopeGlobal,
	)

	criteria := compiler.EmitDiscoveryCriteria(policy.EmitDiscoveryCriteriaInput{
		Facts: policy.Facts{
			TokenExchangeCapable:          true,
			RequiresTokenExchange:         true,
			RequiresHTTPRequestSignatures: true,
		},
		AdvertiseHTTPSig: true,
		TokenEndPoint:    "https://example.com/ocm/token",
	})

	want := []string{spec.CriteriaMustUseHTTPSig, spec.CriteriaMustExchangeToken}
	if len(criteria) != len(want) {
		t.Fatalf("criteria = %v, want %v", criteria, want)
	}
	for i := range want {
		if criteria[i] != want[i] {
			t.Errorf("criteria[%d] = %q, want %q", i, criteria[i], want[i])
		}
	}
}

func TestCompatCompiler_EmitDiscoveryCriteriaOmitsWhenGated(t *testing.T) {
	compiler := policy.NewCompatCompiler(policy.NewCodeFlow(), nil, config.CompatibilityScopeGlobal)

	criteria := compiler.EmitDiscoveryCriteria(policy.EmitDiscoveryCriteriaInput{
		Facts:            policy.NewCodeFlow().Evaluate(),
		AdvertiseHTTPSig: true,
		TokenEndPoint:    "",
	})
	if len(criteria) != 1 || criteria[0] != spec.CriteriaMustUseHTTPSig {
		t.Fatalf("expected only http-sig criterion without token endpoint, got %v", criteria)
	}

	criteria = compiler.EmitDiscoveryCriteria(policy.EmitDiscoveryCriteriaInput{
		Facts: policy.Facts{
			TokenExchangeCapable:          true,
			RequiresTokenExchange:         true,
			RequiresHTTPRequestSignatures: false,
		},
		AdvertiseHTTPSig: true,
		TokenEndPoint:    "https://example.com/ocm/token",
	})
	if len(criteria) != 1 || criteria[0] != spec.CriteriaMustExchangeToken {
		t.Fatalf("criteria = %v, want [%q]", criteria, spec.CriteriaMustExchangeToken)
	}

	criteria = compiler.EmitDiscoveryCriteria(policy.EmitDiscoveryCriteriaInput{
		Facts: policy.Facts{
			TokenExchangeCapable:          true,
			RequiresTokenExchange:         true,
			RequiresHTTPRequestSignatures: true,
		},
		AdvertiseHTTPSig: false,
		TokenEndPoint:    "https://example.com/ocm/token",
	})
	if len(criteria) != 1 || criteria[0] != spec.CriteriaMustExchangeToken {
		t.Fatalf("criteria = %v, want [%q] without http-sig advertise", criteria, spec.CriteriaMustExchangeToken)
	}

	criteria = compiler.EmitDiscoveryCriteria(policy.EmitDiscoveryCriteriaInput{
		Facts: policy.Facts{
			TokenExchangeCapable:          false,
			RequiresTokenExchange:         true,
			RequiresHTTPRequestSignatures: true,
		},
		AdvertiseHTTPSig: true,
		TokenEndPoint:    "https://example.com/ocm/token",
	})
	if len(criteria) != 1 || criteria[0] != spec.CriteriaMustUseHTTPSig {
		t.Fatalf("criteria = %v, want [%q] when TokenExchangeCapable is false", criteria, spec.CriteriaMustUseHTTPSig)
	}
}

func TestCompatCompiler_EmitCapabilitiesUsesSpecConstants(t *testing.T) {
	compiler := policy.NewCompatCompiler(nil, nil, config.CompatibilityScopeGlobal)

	got := compiler.EmitCapabilities(policy.EmitCapabilitiesInput{
		AdvertiseHTTPSig:     true,
		TokenExchangeCapable: true,
		TokenEndPoint:        "https://example.com/ocm/token",
		InvitesEnabled:       true,
		WayfEnabled:          true,
	})
	want := []string{
		spec.CapabilityHTTPSig,
		spec.CapabilityExchangeToken,
		spec.CapabilityInvite,
		spec.CapabilityInviteWAYF,
	}
	if len(got) != len(want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("capabilities[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCompatCompiler_EmitCapabilitiesOmitsWhenGated(t *testing.T) {
	compiler := policy.NewCompatCompiler(nil, nil, config.CompatibilityScopeGlobal)

	got := compiler.EmitCapabilities(policy.EmitCapabilitiesInput{
		AdvertiseHTTPSig: false,
	})
	if len(got) != 0 {
		t.Fatalf("expected no capabilities when all gates false, got %v", got)
	}

	got = compiler.EmitCapabilities(policy.EmitCapabilitiesInput{
		TokenExchangeCapable: true,
		TokenEndPoint:        "",
	})
	if len(got) != 0 {
		t.Fatalf("expected no exchange-token without token endpoint, got %v", got)
	}

	got = compiler.EmitCapabilities(policy.EmitCapabilitiesInput{
		TokenExchangeCapable: false,
		TokenEndPoint:        "https://example.com/ocm/token",
	})
	if len(got) != 0 {
		t.Fatalf("expected no exchange-token when TokenExchangeCapable is false, got %v", got)
	}

	got = compiler.EmitCapabilities(policy.EmitCapabilitiesInput{
		InvitesEnabled: true,
	})
	if len(got) != 1 || got[0] != spec.CapabilityInvite {
		t.Fatalf("capabilities = %v, want [%q]", got, spec.CapabilityInvite)
	}
}

func TestCompatCompiler_SignatureLabelUsesSpecConstant(t *testing.T) {
	compiler := policy.NewCompatCompiler(nil, nil, config.CompatibilityScopeGlobal)
	if got := compiler.SignatureLabel(); got != spec.SignatureLabelOCM {
		t.Fatalf("SignatureLabel() = %q, want %q", got, spec.SignatureLabelOCM)
	}
}

func TestCompatCompiler_EmitShareRequirementsUsesSpecConstants(t *testing.T) {
	compiler := policy.NewCompatCompiler(nil, nil, config.CompatibilityScopeGlobal)

	got := compiler.EmitShareRequirements(policy.EmitShareRequirementsInput{
		IncludesTokenExchange: true,
	})
	if len(got) != 1 || got[0] != spec.RequirementMustExchangeToken {
		t.Fatalf("EmitShareRequirements(true) = %v, want [%q]", got, spec.RequirementMustExchangeToken)
	}
	if compiler.EmitShareRequirements(policy.EmitShareRequirementsInput{
		IncludesTokenExchange: false,
	}) != nil {
		t.Fatal("EmitShareRequirements(false) should be nil")
	}
}

func TestCompatCompiler_RecognizedShareRequirementsUsesSpecConstants(t *testing.T) {
	compiler := policy.NewCompatCompiler(nil, nil, config.CompatibilityScopeGlobal)

	got := compiler.RecognizedShareRequirements()
	want := []string{spec.RequirementMustExchangeToken, spec.RequirementMustUseMFA}
	if len(got) != len(want) {
		t.Fatalf("RecognizedShareRequirements = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCompatCompiler_LocalProfileDelegatesToResolver(t *testing.T) {
	falseVal := false
	cfg := config.PeerMappingConfig{
		RequiresTokenExchangeRequirement: &falseVal,
	}
	compiler := policy.NewCompatCompiler(policy.NewCodeFlow(), &cfg, config.CompatibilityScopeGlobal)
	facts := compiler.LocalProfile("host.example")
	if facts.RequiresTokenExchange {
		t.Error("expected global peer_compat knob to relax RequiresTokenExchange")
	}
}
