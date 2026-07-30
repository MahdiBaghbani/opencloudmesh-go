package config_test

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
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

func TestRFC9421OptionsFromConfig_NonDefaults(t *testing.T) {
	// Clear ambient env override so the signature load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "config.toml")

	tomlContent := `
mode = "dev"
public_origin = "http://localhost:9200"

[signature]
label = "custom-label"
`
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(config.LoaderOptions{ConfigPath: tomlPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Signature.Label != "custom-label" {
		t.Fatalf("Label = %q, want custom-label", cfg.Signature.Label)
	}

	if cfg.Signature.CreatedMaxAgeSeconds <= 0 {
		t.Fatalf("CreatedMaxAgeSeconds = %d", cfg.Signature.CreatedMaxAgeSeconds)
	}

	opts := crypto.RFC9421OptionsFromConfig(cfg.Signature)
	if opts.Label != "custom-label" {
		t.Fatalf("RFC9421Options.Label = %q, want custom-label", opts.Label)
	}

	keyDir := t.TempDir()

	km := crypto.NewKeyManagerWithFragment(filepath.Join(keyDir, "signing.pem"), "https://example.com", cfg.Signature.KidFragment)
	if err := km.LoadOrGenerate(); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
		t.Fatalf("LoadOrGenerate: %v", err)
	}

	signer := crypto.NewRFC9421SignerWithOptions(km, opts)
	verifier := crypto.NewRFC9421Verifier()

	body := []byte(`{"test":"data"}`)

	req, err := http.NewRequest(http.MethodPost, "https://example.com/ocm/shares", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	req.Host = "example.com"
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	if !strings.HasPrefix(sigInput, "custom-label=") {
		t.Fatalf("Signature-Input = %q, want custom-label= prefix", sigInput)
	}

	if !strings.Contains(sigInput, `;tag="ocm"`) {
		t.Fatalf("Signature-Input = %q, want OCM tag parameter", sigInput)
	}

	result := verifier.VerifyRequest(req, body, func(keyID string) (sigalg.ResolvedPublicKey, error) {
		key := km.GetSigningKey()

		return sigalg.ResolvedPublicKey{
			KeyID:     keyID,
			PublicKey: key.PublicKey,
			JWKKty:    "OKP",
			JWKCrv:    "Ed25519",
			JWKAlg:    "Ed25519",
		}, nil
	})
	if !result.Verified {
		t.Fatalf("tag-based verification failed: %v", result.Error)
	}
}

func TestLoad_NormalizesAndDedupesAllowedAlgorithms(t *testing.T) {
	// Clear ambient env override so the algorithm normalization load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
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
	// Clear ambient env override so the empty-array load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
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
			// Clear ambient env override so each rejection case load is deterministic.
			t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
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
