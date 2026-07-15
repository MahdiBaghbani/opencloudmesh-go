package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
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
	want := sigalg.DefaultAllowed()
	if len(sig.AllowedAlgorithms) != len(want) || sig.AllowedAlgorithms[0] != "ed25519" {
		t.Fatalf("AllowedAlgorithms = %v, want %v", sig.AllowedAlgorithms, want)
	}
	foundES256 := false
	for _, alg := range sig.AllowedAlgorithms {
		if alg == sigalg.ECDSAP256SHA256 {
			foundES256 = true
		}
	}
	if !foundES256 {
		t.Fatalf("AllowedAlgorithms missing ecdsa-p256-sha256: %v", sig.AllowedAlgorithms)
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

func TestLoad_NormalizesAndDedupesAllowedAlgorithms(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "config.toml")
	tomlContent := `
mode = "dev"
public_origin = "http://localhost:9200"

[signature]
allowed_algorithms = ["ed25519", "ES256", "ed25519", "rs256"]
`
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(config.LoaderOptions{ConfigPath: tomlPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{sigalg.Ed25519, sigalg.ECDSAP256SHA256, sigalg.RSAPKCS1SHA256}
	if len(cfg.Signature.AllowedAlgorithms) != len(want) {
		t.Fatalf("AllowedAlgorithms = %v, want %v", cfg.Signature.AllowedAlgorithms, want)
	}
	for i, alg := range want {
		if cfg.Signature.AllowedAlgorithms[i] != alg {
			t.Fatalf("AllowedAlgorithms[%d] = %q, want %q (full=%v)", i, cfg.Signature.AllowedAlgorithms[i], alg, cfg.Signature.AllowedAlgorithms)
		}
	}
}

func TestStrictConfig_AllowedAlgorithmsCanonical(t *testing.T) {
	cfg := config.StrictConfig()
	want := sigalg.DefaultAllowed()
	if len(cfg.Signature.AllowedAlgorithms) != len(want) {
		t.Fatalf("AllowedAlgorithms = %v, want %v", cfg.Signature.AllowedAlgorithms, want)
	}
	for i, alg := range want {
		if cfg.Signature.AllowedAlgorithms[i] != alg {
			t.Fatalf("AllowedAlgorithms[%d] = %q, want %q", i, cfg.Signature.AllowedAlgorithms[i], alg)
		}
	}
}

func TestNormalizeSignatureAllowedAlgorithms_Idempotent(t *testing.T) {
	first, err := config.NormalizeSignatureAllowedAlgorithms([]string{"ES256", "ed25519", "ES256"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := config.NormalizeSignatureAllowedAlgorithms(first)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("idempotent length mismatch: %v vs %v", first, second)
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("idempotent mismatch at %d: %q vs %q", i, first[i], second[i])
		}
	}
}

func TestNormalizeSignatureAllowedAlgorithms_RejectsEmpty(t *testing.T) {
	_, err := config.NormalizeSignatureAllowedAlgorithms(nil)
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("nil: got %v, want empty rejection", err)
	}
	_, err = config.NormalizeSignatureAllowedAlgorithms([]string{})
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("empty: got %v, want empty rejection", err)
	}
}

func TestLoad_EmptyAllowedAlgorithmsKeepsDefaults(t *testing.T) {
	// TOML empty array does not overlay (len==0), so preset defaults remain.
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "config.toml")
	tomlContent := `
mode = "dev"
public_origin = "http://localhost:9200"

[signature]
allowed_algorithms = []
`
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(config.LoaderOptions{ConfigPath: tomlPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := sigalg.DefaultAllowed()
	if len(cfg.Signature.AllowedAlgorithms) != len(want) {
		t.Fatalf("AllowedAlgorithms = %v, want defaults %v", cfg.Signature.AllowedAlgorithms, want)
	}
	for i, alg := range want {
		if cfg.Signature.AllowedAlgorithms[i] != alg {
			t.Fatalf("AllowedAlgorithms[%d] = %q, want %q (full=%v)", i, cfg.Signature.AllowedAlgorithms[i], alg, cfg.Signature.AllowedAlgorithms)
		}
	}
}

func TestLoad_RejectsInvalidAllowedAlgorithms(t *testing.T) {
	cases := []struct {
		name    string
		algs    string
		wantSub string
		wantIs  error
	}{
		{name: "whitespace", algs: `["  "]`, wantSub: "must not contain empty values"},
		{name: "empty-entry", algs: `[""]`, wantSub: "must not contain empty values"},
		{name: "hmac", algs: `["hmac-sha256"]`, wantIs: sigalg.ErrSymmetricNotPermitted},
		{name: "unknown", algs: `["no-such-alg"]`, wantSub: "unsupported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tomlPath := filepath.Join(dir, "config.toml")
			tomlContent := `
mode = "dev"
public_origin = "http://localhost:9200"

[signature]
allowed_algorithms = ` + tc.algs + `
`
			if err := os.WriteFile(tomlPath, []byte(tomlContent), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := config.Load(config.LoaderOptions{ConfigPath: tomlPath})
			if err == nil {
				t.Fatal("Load() error = nil, want rejection")
			}
			if tc.wantIs != nil {
				if !errors.Is(err, tc.wantIs) {
					t.Fatalf("Load() error = %v, want errors.Is %v", err, tc.wantIs)
				}
				return
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("Load() error = %v, want substring %q", err, tc.wantSub)
			}
		})
	}
}
