// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func loadJwksURITOML(t *testing.T, tomlContent string) (*config.Config, error) {
	t.Helper()
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	dir := t.TempDir()

	tomlPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0600); err != nil {
		t.Fatal(err)
	}

	return config.Load(config.LoaderOptions{ConfigPath: tomlPath})
}

func TestLoad_SignatureJwksURIDecodes(t *testing.T) {
	cfg, err := loadJwksURITOML(t, `
mode = "dev"
public_origin = "https://cloud.example.com"

[signature]
jwks_uri = "https://cloud.example.com/custom/jwks.json"
`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Signature.JwksURI != "https://cloud.example.com/custom/jwks.json" {
		t.Errorf("Signature.JwksURI = %q, want configured override", cfg.Signature.JwksURI)
	}
}

func TestLoad_SignatureJwksURIEmptyByDefault(t *testing.T) {
	cfg, err := loadJwksURITOML(t, `
mode = "dev"
public_origin = "https://cloud.example.com"
`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Signature.JwksURI != "" {
		t.Errorf("Signature.JwksURI = %q, want empty when unset", cfg.Signature.JwksURI)
	}
}

func TestLoad_RejectsUnknownSignatureKey(t *testing.T) {
	_, err := loadJwksURITOML(t, `
mode = "dev"
public_origin = "https://cloud.example.com"

[signature]
jwks_uri_typo = "https://cloud.example.com/jwks.json"
`)
	if err == nil {
		t.Fatal("Load() error = nil, want rejection of unknown signature key")
	}

	if !strings.Contains(err.Error(), "unsupported keys") {
		t.Fatalf("Load() error = %v, want unsupported keys rejection", err)
	}
}

func TestLoad_RejectsNonAbsoluteSignatureJwksURI(t *testing.T) {
	_, err := loadJwksURITOML(t, `
mode = "dev"
public_origin = "https://cloud.example.com"

[signature]
jwks_uri = "/.well-known/jwks.json"
`)
	if err == nil {
		t.Fatal("Load() error = nil, want rejection of relative jwks_uri")
	}

	if !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("Load() error = %v, want must-be-absolute rejection", err)
	}
}

func TestLoad_RejectsHTTPSignatureJwksURIOutsideDev(t *testing.T) {
	_, err := loadJwksURITOML(t, `
mode = "dev"
public_origin = "https://cloud.example.com"

[signature]
jwks_uri = "http://cloud.example.com/jwks.json"
`)
	if err == nil {
		t.Fatal("Load() error = nil, want rejection of http jwks_uri with https public_origin")
	}

	if !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("Load() error = %v, want must-use-https rejection", err)
	}
}

func TestLoad_AllowsHTTPSignatureJwksURIWithDevHTTPOrigin(t *testing.T) {
	cfg, err := loadJwksURITOML(t, `
mode = "dev"
public_origin = "http://localhost:9200"

[signature]
jwks_uri = "http://localhost:9200/jwks.json"
`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Signature.JwksURI != "http://localhost:9200/jwks.json" {
		t.Errorf("Signature.JwksURI = %q, want configured http override", cfg.Signature.JwksURI)
	}
}

func TestLoad_RejectsSignatureJwksURIWithCredentials(t *testing.T) {
	_, err := loadJwksURITOML(t, `
mode = "dev"
public_origin = "https://cloud.example.com"

[signature]
jwks_uri = "https://user:pass@cloud.example.com/jwks.json"
`)
	if err == nil {
		t.Fatal("Load() error = nil, want rejection of jwks_uri with credentials")
	}

	msg := err.Error()
	if !strings.Contains(msg, "credentials") {
		t.Fatalf("Load() error = %v, want credentials rejection", err)
	}

	if strings.Contains(msg, "user:pass") || strings.Contains(msg, "user@") {
		t.Fatalf("Load() error = %v, must not echo credential userinfo", err)
	}
}

func TestLoad_RejectsOpaqueSignatureJwksURIWithoutEchoingCredentials(t *testing.T) {
	// Opaque URLs can carry credential-like text in u.Opaque; rejection must
	// not interpolate the configured URI into the error.
	_, err := loadJwksURITOML(t, `
mode = "dev"
public_origin = "https://cloud.example.com"

[signature]
jwks_uri = "https:user:pass@cloud.example.com/jwks.json"
`)
	if err == nil {
		t.Fatal("Load() error = nil, want rejection of opaque jwks_uri")
	}

	msg := err.Error()
	if !strings.Contains(msg, "must be absolute") {
		t.Fatalf("Load() error = %v, want must-be-absolute rejection", err)
	}

	if strings.Contains(msg, "user:pass") || strings.Contains(msg, "user@") {
		t.Fatalf("Load() error = %v, must not echo opaque credential text", err)
	}
}

func TestLoad_RejectsMalformedSignatureJwksURIWithoutEchoingRaw(t *testing.T) {
	const raw = "https://cloud.example.com/%zz"

	_, err := loadJwksURITOML(t, `
mode = "dev"
public_origin = "https://cloud.example.com"

[signature]
jwks_uri = "https://cloud.example.com/%zz"
`)
	if err == nil {
		t.Fatal("Load() error = nil, want rejection of malformed jwks_uri")
	}

	msg := err.Error()
	if !strings.Contains(msg, "malformed") {
		t.Fatalf("Load() error = %v, want malformed rejection", err)
	}

	if strings.Contains(msg, raw) || strings.Contains(msg, "%zz") {
		t.Fatalf("Load() error = %v, must not echo raw malformed URI", err)
	}
}

func TestLoad_RejectsSignatureJwksURIWithFragment(t *testing.T) {
	_, err := loadJwksURITOML(t, `
mode = "dev"
public_origin = "https://cloud.example.com"

[signature]
jwks_uri = "https://cloud.example.com/jwks.json#key-1"
`)
	if err == nil {
		t.Fatal("Load() error = nil, want rejection of jwks_uri with fragment")
	}

	if !strings.Contains(err.Error(), "fragment") {
		t.Fatalf("Load() error = %v, want fragment rejection", err)
	}
}

func TestLoad_RejectsSignatureJwksURIWithBareFragment(t *testing.T) {
	_, err := loadJwksURITOML(t, `
mode = "dev"
public_origin = "https://cloud.example.com"

[signature]
jwks_uri = "https://cloud.example.com/jwks.json#"
`)
	if err == nil {
		t.Fatal("Load() error = nil, want rejection of jwks_uri with bare fragment")
	}

	if !strings.Contains(err.Error(), "fragment") {
		t.Fatalf("Load() error = %v, want fragment rejection", err)
	}
}

func TestLoad_RejectsNonHTTPSchemeSignatureJwksURI(t *testing.T) {
	_, err := loadJwksURITOML(t, `
mode = "dev"
public_origin = "https://cloud.example.com"

[signature]
jwks_uri = "ftp://cloud.example.com/jwks"
`)
	if err == nil {
		t.Fatal("Load() error = nil, want rejection of non-http jwks_uri scheme")
	}

	msg := err.Error()
	if !strings.Contains(msg, `scheme "ftp" is not allowed`) {
		t.Fatalf("Load() error = %v, want scheme-not-allowed rejection", err)
	}
}

func TestLoad_RejectsSchemeRelativeSignatureJwksURI(t *testing.T) {
	_, err := loadJwksURITOML(t, `
mode = "dev"
public_origin = "https://cloud.example.com"

[signature]
jwks_uri = "//cloud.example.com/jwks"
`)
	if err == nil {
		t.Fatal("Load() error = nil, want rejection of scheme-relative jwks_uri")
	}

	if !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("Load() error = %v, want must-be-absolute rejection", err)
	}
}
