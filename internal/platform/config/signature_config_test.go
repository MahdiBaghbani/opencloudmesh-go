package config_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestDefaultSignatureConfig_IETFDefaults(t *testing.T) {
	sig := config.DefaultSignatureConfig()
	if sig.Label != "ocm" {
		t.Fatalf("Label = %q", sig.Label)
	}
	if sig.KidFragment != "key1" {
		t.Fatalf("KidFragment = %q", sig.KidFragment)
	}
	if sig.CreatedMaxAgeSeconds != config.DefaultSignatureCreatedMaxAge {
		t.Fatalf("CreatedMaxAgeSeconds = %d", sig.CreatedMaxAgeSeconds)
	}
	if len(sig.AllowedAlgorithms) != 1 || sig.AllowedAlgorithms[0] != "ed25519" {
		t.Fatalf("AllowedAlgorithms = %v", sig.AllowedAlgorithms)
	}
}

func TestLoad_AppliesSignatureDefaults(t *testing.T) {
	cfg, err := config.Load(config.LoaderOptions{ModeFlag: "strict"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Signature.Label != "ocm" {
		t.Fatalf("Label = %q", cfg.Signature.Label)
	}
	if cfg.Signature.CreatedMaxAgeSeconds <= 0 {
		t.Fatalf("CreatedMaxAgeSeconds = %d", cfg.Signature.CreatedMaxAgeSeconds)
	}
}
