package wiring

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// TestResolveInputs_CopiesSignatureJwksURI confirms cfg.Signature.JwksURI
// flows unchanged into resolve.ResolveInputs.JwksURIOverride, the same field
// resolve.Resolve threads into discovery.BuildParams.JwksURI.
func TestResolveInputs_CopiesSignatureJwksURI(t *testing.T) {
	cfg := config.DevConfig()
	cfg.Signature.JwksURI = "https://cloud.example.com/custom/jwks.json"

	d := &Deps{}

	in := resolveInputs(cfg, d)
	if in.JwksURIOverride != "https://cloud.example.com/custom/jwks.json" {
		t.Errorf("JwksURIOverride = %q, want configured override", in.JwksURIOverride)
	}
}

// TestResolveInputs_EmptySignatureJwksURILeavesOverrideEmpty confirms an
// unset override does not synthesize a value.
func TestResolveInputs_EmptySignatureJwksURILeavesOverrideEmpty(t *testing.T) {
	cfg := config.DevConfig()

	d := &Deps{}

	in := resolveInputs(cfg, d)
	if in.JwksURIOverride != "" {
		t.Errorf("JwksURIOverride = %q, want empty when signature.jwks_uri is unset", in.JwksURIOverride)
	}
}
