package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/ocm/configfixture"
)

func assertCommonPresetShape(t *testing.T, cfg *config.Config, mode string) {
	t.Helper()

	if cfg.Mode != mode {
		t.Errorf("mode = %q, want %q", cfg.Mode, mode)
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
	if cfg.TokenExchange.Path != "token" {
		t.Errorf("token exchange path = %q, want token", cfg.TokenExchange.Path)
	}
}

func assertAllFactsTrue(t *testing.T, facts policy.Facts) {
	t.Helper()
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

func TestStrictPreset_FinalShape(t *testing.T) {
	cfg := config.StrictConfig()
	if cfg == nil {
		t.Fatal("expected StrictConfig to load a config")
	}

	assertCommonPresetShape(t, cfg, "strict")
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

	assertAllFactsTrue(t, policy.NewCodeFlow().Evaluate())
	if cfg.OCM.CodeFlow.IncludesTokenExchangeRequirement != nil ||
		cfg.OCM.CodeFlow.RequiresTokenExchangeRequirement != nil ||
		cfg.OCM.CodeFlow.RequiresHTTPRequestSignatures != nil {
		t.Fatalf("strict preset code-flow knobs must stay unset, got %+v", cfg.OCM.CodeFlow)
	}
}

func TestDevPreset_FinalShape(t *testing.T) {
	cfg := config.DevConfig()
	if cfg == nil {
		t.Fatal("expected DevConfig to load a config")
	}

	assertCommonPresetShape(t, cfg, "dev")
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

	assertAllFactsTrue(t, policy.NewCodeFlow().Evaluate())
}

// TestCodeFlow_EvaluateDefaultsStrict confirms unset knobs on a non-nil
// CodeFlow evaluate to all-true facts.
func TestCodeFlow_EvaluateDefaultsStrict(t *testing.T) {
	assertAllFactsTrue(t, policy.NewCodeFlow().Evaluate())
}

// TestCodeFlow_NilSafe confirms a nil *CodeFlow is safe to call and returns
// all-false Facts (strict-off).
func TestCodeFlow_NilSafe(t *testing.T) {
	var c *policy.CodeFlow
	facts := c.Evaluate()
	if facts.TokenExchangeCapable || facts.RequiresTokenExchange ||
		facts.IncludesTokenExchangeRequirement || facts.RequiresHTTPRequestSignatures {
		t.Fatalf("expected all-false Facts from nil *CodeFlow, got %+v", facts)
	}
}

func TestCodeFlow_LegacyVoluntary_IncludesFalse(t *testing.T) {
	facts := configfixture.CodeFlowLegacyVoluntary().Evaluate()
	if facts.IncludesTokenExchangeRequirement {
		t.Fatal("expected IncludesTokenExchangeRequirement false")
	}
	if !facts.TokenExchangeCapable {
		t.Error("expected TokenExchangeCapable true")
	}
	if !facts.RequiresTokenExchange {
		t.Error("expected RequiresTokenExchange true")
	}
	if !facts.RequiresHTTPRequestSignatures {
		t.Error("expected RequiresHTTPRequestSignatures true")
	}
}

func TestCodeFlow_KnobRelaxationAndEnforcement(t *testing.T) {
	falseVal := false
	trueVal := true

	t.Run("false relaxes each knob", func(t *testing.T) {
		cf := &policy.CodeFlow{
			IncludesTokenExchangeRequirement: &falseVal,
			RequiresTokenExchangeRequirement: &falseVal,
			RequiresHTTPRequestSignatures:    &falseVal,
		}
		facts := cf.Evaluate()
		if facts.IncludesTokenExchangeRequirement || facts.RequiresTokenExchange ||
			facts.RequiresHTTPRequestSignatures {
			t.Fatalf("expected relaxed knobs false, got %+v", facts)
		}
		if !facts.TokenExchangeCapable {
			t.Error("TokenExchangeCapable must stay true on a non-nil CodeFlow")
		}
	})

	t.Run("true enforces each knob", func(t *testing.T) {
		cf := &policy.CodeFlow{
			IncludesTokenExchangeRequirement: &trueVal,
			RequiresTokenExchangeRequirement: &trueVal,
			RequiresHTTPRequestSignatures:    &trueVal,
		}
		assertAllFactsTrue(t, cf.Evaluate())
	})
}

func TestCodeFlow_ConfigLoadPointers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "code-flow.toml")
	content := `
mode = "dev"

[ocm.code_flow]
includes_token_exchange_requirement = false
requires_token_exchange_requirement = true
requires_http_request_signatures = false
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(config.LoaderOptions{ConfigPath: path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OCM.CodeFlow.IncludesTokenExchangeRequirement == nil ||
		*cfg.OCM.CodeFlow.IncludesTokenExchangeRequirement {
		t.Fatalf("includes knob = %v, want false", cfg.OCM.CodeFlow.IncludesTokenExchangeRequirement)
	}
	if cfg.OCM.CodeFlow.RequiresTokenExchangeRequirement == nil ||
		!*cfg.OCM.CodeFlow.RequiresTokenExchangeRequirement {
		t.Fatalf("requires-token knob = %v, want true", cfg.OCM.CodeFlow.RequiresTokenExchangeRequirement)
	}
	if cfg.OCM.CodeFlow.RequiresHTTPRequestSignatures == nil ||
		*cfg.OCM.CodeFlow.RequiresHTTPRequestSignatures {
		t.Fatalf("http-sig knob = %v, want false", cfg.OCM.CodeFlow.RequiresHTTPRequestSignatures)
	}

	cf := &policy.CodeFlow{
		IncludesTokenExchangeRequirement: cfg.OCM.CodeFlow.IncludesTokenExchangeRequirement,
		RequiresTokenExchangeRequirement: cfg.OCM.CodeFlow.RequiresTokenExchangeRequirement,
		RequiresHTTPRequestSignatures:    cfg.OCM.CodeFlow.RequiresHTTPRequestSignatures,
	}
	facts := cf.Evaluate()
	if facts.IncludesTokenExchangeRequirement || !facts.RequiresTokenExchange ||
		facts.RequiresHTTPRequestSignatures || !facts.TokenExchangeCapable {
		t.Fatalf("evaluated facts = %+v", facts)
	}
}

func TestCodeFlow_UnsetTOMLKeepsNilKnobs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty-code-flow.toml")
	if err := os.WriteFile(path, []byte("mode = \"dev\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(config.LoaderOptions{ConfigPath: path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OCM.CodeFlow.IncludesTokenExchangeRequirement != nil ||
		cfg.OCM.CodeFlow.RequiresTokenExchangeRequirement != nil ||
		cfg.OCM.CodeFlow.RequiresHTTPRequestSignatures != nil {
		t.Fatalf("unset TOML must leave knobs nil, got %+v", cfg.OCM.CodeFlow)
	}
	assertAllFactsTrue(t, (&policy.CodeFlow{
		IncludesTokenExchangeRequirement: cfg.OCM.CodeFlow.IncludesTokenExchangeRequirement,
		RequiresTokenExchangeRequirement: cfg.OCM.CodeFlow.RequiresTokenExchangeRequirement,
		RequiresHTTPRequestSignatures:    cfg.OCM.CodeFlow.RequiresHTTPRequestSignatures,
	}).Evaluate())
}

func TestDiscovery_OmitsMustUseHTTPSigWhenRequiresFalse(t *testing.T) {
	falseVal := false
	cf := &policy.CodeFlow{RequiresHTTPRequestSignatures: &falseVal}
	facts := cf.Evaluate()

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:               "https://example.com/ocm",
		WebDAVRoot:             "/webdav/ocm/",
		AdvertiseHTTPSig:       true,
		RequiresHTTPSignatures: facts.RequiresHTTPRequestSignatures,
	}, nil)
	if disc.HasCriteria(spec.CriteriaMustUseHTTPSig) {
		t.Error("did not expect must-use-http-sig when requires_http_request_signatures is false")
	}
	if !disc.IsHTTPSigCapable() {
		t.Error("expected http-sig capability when AdvertiseHTTPSig is true")
	}
}
