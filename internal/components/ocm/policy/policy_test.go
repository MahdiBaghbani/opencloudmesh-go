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
	if cfg.OutboundHTTP.SSRF.Mode != "strict" {
		t.Errorf("outbound SSRF mode = %q, want strict", cfg.OutboundHTTP.SSRF.Mode)
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

	facts := policy.NewCodeFlow().Evaluate()
	if !facts.TokenExchangeCapable {
		t.Error("expected TokenExchangeCapable true")
	}
	if !facts.RequiresTokenExchange {
		t.Error("expected RequiresTokenExchange true")
	}
	if !facts.IncludesTokenExchangeRequirement {
		t.Error("expected IncludesTokenExchangeRequirement true")
	}
	if !facts.RequiresHTTPRequestSignatures {
		t.Error("expected RequiresHTTPRequestSignatures true")
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
	if cfg.OutboundHTTP.SSRF.Mode != "off" {
		t.Errorf("outbound SSRF mode = %q, want off", cfg.OutboundHTTP.SSRF.Mode)
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

	facts := policy.NewCodeFlow().Evaluate()
	if !facts.TokenExchangeCapable {
		t.Error("expected TokenExchangeCapable true under the dev preset")
	}
	if !facts.RequiresTokenExchange {
		t.Error("expected RequiresTokenExchange true under the dev preset")
	}
	if !facts.IncludesTokenExchangeRequirement {
		t.Error("expected IncludesTokenExchangeRequirement true under the dev preset")
	}
	if !facts.RequiresHTTPRequestSignatures {
		t.Error("expected RequiresHTTPRequestSignatures true under the dev preset")
	}
}

// TestCodeFlow_EvaluateReturnsFixedFacts confirms the single local policy
// type reports the code-flow facts as fixed constants.
func TestCodeFlow_EvaluateReturnsFixedFacts(t *testing.T) {
	facts := policy.NewCodeFlow().Evaluate()
	if !facts.TokenExchangeCapable || !facts.RequiresTokenExchange ||
		!facts.IncludesTokenExchangeRequirement || !facts.RequiresHTTPRequestSignatures {
		t.Fatalf("expected fixed local code-flow facts, got %+v", facts)
	}
}

// TestCodeFlow_NilSafe confirms a nil *CodeFlow is safe to call and returns
// the fixed facts.
func TestCodeFlow_NilSafe(t *testing.T) {
	var c *policy.CodeFlow
	facts := c.Evaluate()
	if !facts.TokenExchangeCapable || !facts.RequiresTokenExchange ||
		!facts.IncludesTokenExchangeRequirement || !facts.RequiresHTTPRequestSignatures {
		t.Fatalf("expected fixed facts from nil *CodeFlow, got %+v", facts)
	}
}
