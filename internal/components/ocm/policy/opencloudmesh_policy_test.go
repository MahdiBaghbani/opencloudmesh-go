package policy_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestOpenCloudMeshPolicyEvaluate_AllEnabled(t *testing.T) {
	tokenExchangeEnabled := true
	cfg := &config.Config{
		TokenExchange:       config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled},
		WebDAVTokenExchange: config.WebDAVTokenExchangeConfig{Mode: "strict"},
		PeerPolicy:          "prefer-strict",
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
		t.Error("expected RequiresTokenExchange false in dev (off mode)")
	}
	if eval.PeerPolicy != "prefer-strict" {
		t.Errorf("expected PeerPolicy prefer-strict, got %q", eval.PeerPolicy)
	}
}

func TestOpenCloudMeshPolicyEvaluate_TokenExchangeDisabled(t *testing.T) {
	tokenExchangeEnabled := false
	cfg := &config.Config{
		TokenExchange:       config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled},
		WebDAVTokenExchange: config.WebDAVTokenExchangeConfig{Mode: "off"},
		PeerPolicy:          "legacy",
	}
	eval := policy.NewOpenCloudMeshPolicy(cfg).Evaluate()

	if eval.TokenExchangeCapable {
		t.Error("expected TokenExchangeCapable false when token exchange disabled")
	}
	if eval.RequiresTokenExchange {
		t.Error("expected RequiresTokenExchange false when mode=off")
	}
}

func TestOpenCloudMeshPolicyEvaluate_LenientModeNotStrict(t *testing.T) {
	tokenExchangeEnabled := true
	cfg := &config.Config{
		TokenExchange:       config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled},
		WebDAVTokenExchange: config.WebDAVTokenExchangeConfig{Mode: "lenient"},
		PeerPolicy:          "legacy",
	}
	eval := policy.NewOpenCloudMeshPolicy(cfg).Evaluate()

	if !eval.TokenExchangeCapable {
		t.Error("expected TokenExchangeCapable true")
	}
	if eval.RequiresTokenExchange {
		t.Error("expected RequiresTokenExchange false for lenient mode")
	}
}

func TestOpenCloudMeshPolicyEvaluate_StrictPolicy(t *testing.T) {
	tokenExchangeEnabled := true
	cfg := &config.Config{
		TokenExchange:       config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled},
		WebDAVTokenExchange: config.WebDAVTokenExchangeConfig{Mode: "strict"},
		PeerPolicy:          "strict",
	}
	eval := policy.NewOpenCloudMeshPolicy(cfg).Evaluate()

	if eval.PeerPolicy != "strict" {
		t.Errorf("expected PeerPolicy strict, got %q", eval.PeerPolicy)
	}
}

func TestOpenCloudMeshPolicyEvaluate_NilTokenExchangeEnabled(t *testing.T) {
	cfg := &config.Config{
		WebDAVTokenExchange: config.WebDAVTokenExchangeConfig{Mode: "off"},
		PeerPolicy:          "legacy",
	}
	eval := policy.NewOpenCloudMeshPolicy(cfg).Evaluate()

	if eval.TokenExchangeCapable {
		t.Error("expected TokenExchangeCapable false when TokenExchange.Enabled is nil")
	}
}
