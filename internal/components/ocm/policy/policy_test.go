package policy_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func assertCommonPresetShape(t *testing.T, cfg *config.Config, mode, scope string) {
	t.Helper()

	if cfg.Mode != mode {
		t.Errorf("mode = %q, want %q", cfg.Mode, mode)
	}
	if cfg.CompatibilityScope != scope {
		t.Errorf("scope = %q, want %q", cfg.CompatibilityScope, scope)
	}
	if cfg.PublicOrigin != "https://localhost:9200" {
		t.Errorf("public origin = %q, want https://localhost:9200", cfg.PublicOrigin)
	}
	if cfg.ListenAddr != ":9200" {
		t.Errorf("listen address = %q, want :9200", cfg.ListenAddr)
	}
	if cfg.TLS.HTTPPort != 9280 || cfg.TLS.HTTPSPort != 9200 {
		t.Errorf("TLS ports = (%d, %d), want (9280, 9200)", cfg.TLS.HTTPPort, cfg.TLS.HTTPSPort)
	}
	if cfg.TLS.SelfSignedDir != ".ocm/certs" {
		t.Errorf("TLS self-signed directory = %q, want .ocm/certs", cfg.TLS.SelfSignedDir)
	}
	if cfg.OutboundHTTP.TimeoutMS != config.DefaultOutboundTimeoutMS {
		t.Errorf("outbound timeout = %d, want %d", cfg.OutboundHTTP.TimeoutMS, config.DefaultOutboundTimeoutMS)
	}
	if cfg.OutboundHTTP.ConnectTimeoutMS != config.DefaultOutboundConnectTimeoutMS {
		t.Errorf(
			"outbound connect timeout = %d, want %d",
			cfg.OutboundHTTP.ConnectTimeoutMS,
			config.DefaultOutboundConnectTimeoutMS,
		)
	}
	if cfg.OutboundHTTP.MaxResponseBytes != config.DefaultMaxResponseBytes {
		t.Errorf(
			"outbound max response bytes = %d, want %d",
			cfg.OutboundHTTP.MaxResponseBytes,
			config.DefaultMaxResponseBytes,
		)
	}
	if cfg.Signature.InboundMode != "strict" {
		t.Errorf("signature inbound mode = %q, want strict", cfg.Signature.InboundMode)
	}
	if cfg.Signature.OutboundMode != "strict" {
		t.Errorf("signature outbound mode = %q, want strict", cfg.Signature.OutboundMode)
	}
	if cfg.Signature.PeerProfileLevelOverride != "off" {
		t.Errorf("signature peer profile override = %q, want off", cfg.Signature.PeerProfileLevelOverride)
	}
	if cfg.Signature.AllowMismatch {
		t.Error("signature mismatch allowance must be false")
	}
	if cfg.Signature.Label != config.DefaultSignatureLabel {
		t.Errorf("signature label = %q, want %q", cfg.Signature.Label, config.DefaultSignatureLabel)
	}
	if cfg.Signature.KidFragment != config.DefaultSignatureKidFragment {
		t.Errorf("signature key fragment = %q, want %q", cfg.Signature.KidFragment, config.DefaultSignatureKidFragment)
	}
	if cfg.TokenExchange.Enabled == nil || !*cfg.TokenExchange.Enabled {
		t.Fatal("token exchange must be enabled")
	}
	if cfg.TokenExchange.Path != "token" {
		t.Errorf("token exchange path = %q, want token", cfg.TokenExchange.Path)
	}
	if !cfg.RequireTokenExchange {
		t.Error("token exchange must be required")
	}
	if cfg.PeerPolicy != "strict" {
		t.Errorf("peer policy = %q, want strict", cfg.PeerPolicy)
	}
}

func TestStrictPreset_FinalShape(t *testing.T) {
	cfg := config.StrictConfig()
	if cfg == nil {
		t.Fatal("expected StrictConfig to load a config")
	}

	assertCommonPresetShape(t, cfg, "strict", "none")
	if cfg.TLS.Mode != "selfsigned" {
		t.Errorf("TLS mode = %q, want selfsigned", cfg.TLS.Mode)
	}
	if cfg.TLS.ACME.Directory != "https://acme-v02.api.letsencrypt.org/directory" {
		t.Errorf("ACME directory = %q, want production directory", cfg.TLS.ACME.Directory)
	}
	if cfg.TLS.ACME.UseStaging {
		t.Error("strict preset must not use ACME staging")
	}
	if cfg.OutboundHTTP.SSRF.Mode != "strict" || cfg.OutboundHTTP.DerivedSSRFMode != "strict" {
		t.Errorf(
			"outbound SSRF modes = (%q, %q), want (strict, strict)",
			cfg.OutboundHTTP.SSRF.Mode,
			cfg.OutboundHTTP.DerivedSSRFMode,
		)
	}
	if cfg.OutboundHTTP.MaxRedirects != config.DefaultOutboundMaxRedirects ||
		cfg.OutboundHTTP.InsecureSkipVerify ||
		!cfg.OutboundHTTP.ProxyEnvFallback {
		t.Errorf(
			"strict outbound transport = redirects:%d skip_verify:%t proxy_env:%t",
			cfg.OutboundHTTP.MaxRedirects,
			cfg.OutboundHTTP.InsecureSkipVerify,
			cfg.OutboundHTTP.ProxyEnvFallback,
		)
	}

	facts := policy.NewLocalCodeFlowPolicy(cfg).Evaluate()
	if !facts.TokenExchangeCapable {
		t.Error("expected TokenExchangeCapable true")
	}
	if !facts.RequiresTokenExchange {
		t.Error("expected RequiresTokenExchange true")
	}
	if !facts.IncludesRequirement {
		t.Error("expected IncludesRequirement true")
	}
}

func TestDevPreset_FinalShape(t *testing.T) {
	cfg := config.DevConfig()
	if cfg == nil {
		t.Fatal("expected DevConfig to load a config")
	}

	assertCommonPresetShape(t, cfg, "dev", "scoped")
	if cfg.TLS.Mode != "off" {
		t.Errorf("TLS mode = %q, want off", cfg.TLS.Mode)
	}
	if cfg.TLS.ACME.Directory != "https://acme-staging-v02.api.letsencrypt.org/directory" {
		t.Errorf("ACME directory = %q, want staging directory", cfg.TLS.ACME.Directory)
	}
	if !cfg.TLS.ACME.UseStaging {
		t.Error("dev preset must use ACME staging")
	}
	if cfg.OutboundHTTP.SSRF.Mode != "off" || cfg.OutboundHTTP.DerivedSSRFMode != "off" {
		t.Errorf(
			"outbound SSRF modes = (%q, %q), want (off, off)",
			cfg.OutboundHTTP.SSRF.Mode,
			cfg.OutboundHTTP.DerivedSSRFMode,
		)
	}
	if cfg.OutboundHTTP.MaxRedirects != 3 ||
		!cfg.OutboundHTTP.InsecureSkipVerify ||
		cfg.OutboundHTTP.ProxyEnvFallback {
		t.Errorf(
			"dev outbound transport = redirects:%d skip_verify:%t proxy_env:%t",
			cfg.OutboundHTTP.MaxRedirects,
			cfg.OutboundHTTP.InsecureSkipVerify,
			cfg.OutboundHTTP.ProxyEnvFallback,
		)
	}

	facts := policy.NewLocalCodeFlowPolicy(cfg).Evaluate()
	if !facts.TokenExchangeCapable {
		t.Error("expected TokenExchangeCapable true under the dev preset")
	}
	if !facts.RequiresTokenExchange {
		t.Error("expected RequiresTokenExchange true under the dev preset")
	}
	if !facts.IncludesRequirement {
		t.Error("expected IncludesRequirement true under the dev preset")
	}
}

// TestLocalCodeFlowPolicy_FixedFacts confirms the single local policy type
// reports the three code-flow facts as constants regardless of input.
func TestLocalCodeFlowPolicy_FixedFacts(t *testing.T) {
	inputs := []*config.Config{config.StrictConfig(), config.DevConfig(), nil}
	for _, cfg := range inputs {
		facts := policy.NewLocalCodeFlowPolicy(cfg).Evaluate()
		if !facts.TokenExchangeCapable || !facts.RequiresTokenExchange || !facts.IncludesRequirement {
			t.Fatalf("expected fixed local code-flow facts regardless of input, got %+v for cfg=%v", facts, cfg)
		}
	}
}
