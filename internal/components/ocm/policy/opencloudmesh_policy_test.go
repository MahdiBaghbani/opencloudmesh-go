package policy_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestOpenCloudMeshPolicyEvaluate_AllEnabled(t *testing.T) {
	tokenExchangeEnabled := true
	cfg := &config.Config{
		TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled},
		RequireTokenExchange: true,
		PeerPolicy:           "prefer-strict",
	}
	eval := policy.NewOpenCloudMeshPolicy(cfg).Evaluate()

	if !eval.TokenExchangeCapable {
		t.Error("expected TokenExchangeCapable true")
	}
	if !eval.RequiresTokenExchange {
		t.Error("expected RequiresTokenExchange true")
	}
	if eval.PeerPolicy != "prefer-strict" {
		t.Errorf("expected PeerPolicy prefer-strict, got %q", eval.PeerPolicy)
	}
}

func TestOpenCloudMeshPolicyEvaluate_AllDefaults(t *testing.T) {
	cfg := config.DevConfig()
	eval := policy.NewOpenCloudMeshPolicy(cfg).Evaluate()

	if !eval.TokenExchangeCapable {
		t.Error("expected TokenExchangeCapable true by default")
	}
	if eval.RequiresTokenExchange {
		t.Error("expected RequiresTokenExchange false in dev preset")
	}
	if eval.PeerPolicy != "prefer-strict" {
		t.Errorf("expected PeerPolicy prefer-strict, got %q", eval.PeerPolicy)
	}
}

func TestOpenCloudMeshPolicyEvaluate_TokenExchangeDisabled(t *testing.T) {
	tokenExchangeEnabled := false
	cfg := &config.Config{
		TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled},
		RequireTokenExchange: false,
		PeerPolicy:           "legacy",
	}
	eval := policy.NewOpenCloudMeshPolicy(cfg).Evaluate()

	if eval.TokenExchangeCapable {
		t.Error("expected TokenExchangeCapable false when token exchange disabled")
	}
	if eval.RequiresTokenExchange {
		t.Error("expected RequiresTokenExchange false when require_token_exchange=false")
	}
}

func TestOpenCloudMeshPolicyEvaluate_RequireTokenExchangeFalse(t *testing.T) {
	tokenExchangeEnabled := true
	cfg := &config.Config{
		TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled},
		RequireTokenExchange: false,
		PeerPolicy:           "legacy",
	}
	eval := policy.NewOpenCloudMeshPolicy(cfg).Evaluate()

	if !eval.TokenExchangeCapable {
		t.Error("expected TokenExchangeCapable true")
	}
	if eval.RequiresTokenExchange {
		t.Error("expected RequiresTokenExchange false when require_token_exchange=false")
	}
}

func TestOpenCloudMeshPolicyEvaluate_StrictPolicy(t *testing.T) {
	tokenExchangeEnabled := true
	cfg := &config.Config{
		TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled},
		RequireTokenExchange: true,
		PeerPolicy:           "strict",
	}
	eval := policy.NewOpenCloudMeshPolicy(cfg).Evaluate()

	if eval.PeerPolicy != "strict" {
		t.Errorf("expected PeerPolicy strict, got %q", eval.PeerPolicy)
	}
}

func TestOpenCloudMeshPolicyEvaluate_NilTokenExchangeEnabled(t *testing.T) {
	cfg := &config.Config{
		RequireTokenExchange: false,
		PeerPolicy:           "legacy",
	}
	eval := policy.NewOpenCloudMeshPolicy(cfg).Evaluate()

	if eval.TokenExchangeCapable {
		t.Error("expected TokenExchangeCapable false when TokenExchange.Enabled is nil")
	}
}
