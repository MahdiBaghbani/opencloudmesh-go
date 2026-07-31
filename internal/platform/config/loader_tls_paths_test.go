// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tlsPathExpectation holds the expected TLS path fields for one loader case.
type tlsPathExpectation struct {
	tlsDir       string
	selfSigned   string
	acmeStorage  string
	signatureKey string
}

// loadTLSPathConfig writes tomlContent to a temp config and loads it with the
// ambient env fallback cleared so the TLS path load is deterministic.
func loadTLSPathConfig(t *testing.T, tomlContent string) *Config {
	t.Helper()

	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	return cfg
}

// assertTLSPaths verifies the four TLS path fields on cfg.
func assertTLSPaths(t *testing.T, cfg *Config, want tlsPathExpectation) {
	t.Helper()

	if cfg.TLS.TLSDir != want.tlsDir {
		t.Errorf("expected TLSDir %q, got %q", want.tlsDir, cfg.TLS.TLSDir)
	}

	if cfg.TLS.SelfSignedDir != want.selfSigned {
		t.Errorf("expected SelfSignedDir %q, got %q", want.selfSigned, cfg.TLS.SelfSignedDir)
	}

	if cfg.TLS.ACME.StorageDir != want.acmeStorage {
		t.Errorf("expected ACME StorageDir %q, got %q", want.acmeStorage, cfg.TLS.ACME.StorageDir)
	}

	if cfg.Signature.KeyPath != want.signatureKey {
		t.Errorf("expected Signature KeyPath %q, got %q", want.signatureKey, cfg.Signature.KeyPath)
	}
}

func TestLoad_TLSDir_Absent_NoChange(t *testing.T) {
	// No tls_dir in TOML; paths stay at preset defaults.
	cfg := loadTLSPathConfig(t, `mode = "strict"
public_origin = "https://localhost:9200"
`)

	assertTLSPaths(t, cfg, tlsPathExpectation{
		tlsDir:       "",
		selfSigned:   ".ocm/certs",
		acmeStorage:  ".ocm/acme",
		signatureKey: ".ocm/keys/signing.pem",
	})
}

func TestLoad_TLSDir_NotInTOML_NoDerivation(t *testing.T) {
	// Even with [tls] present, derivation must not run unless tls_dir key is present.
	cfg := loadTLSPathConfig(t, `mode = "strict"
public_origin = "https://localhost:9200"

[tls]
mode = "selfsigned"
`)

	assertTLSPaths(t, cfg, tlsPathExpectation{
		tlsDir:       "",
		selfSigned:   ".ocm/certs",
		acmeStorage:  ".ocm/acme",
		signatureKey: ".ocm/keys/signing.pem",
	})
}

func TestLoad_TLSDir_Present_DerivesDefaults(t *testing.T) {
	// tls_dir set; derives self_signed_dir, acme.storage_dir, signature.key_path.
	cfg := loadTLSPathConfig(t, `mode = "strict"
public_origin = "https://localhost:9200"

[tls]
tls_dir = "/data/tls"
`)

	assertTLSPaths(t, cfg, tlsPathExpectation{
		tlsDir:       "/data/tls",
		selfSigned:   "/data/tls/certs",
		acmeStorage:  "/data/tls/acme",
		signatureKey: "/data/tls/keys/signing.pem",
	})
}

func TestLoad_TLSDir_ExplicitOverride(t *testing.T) {
	// Clear ambient env override so the explicit-override load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	// tls_dir set but self_signed_dir also explicitly set; uses explicit value
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"

[tls]
tls_dir = "/data/tls"
self_signed_dir = "/custom/certs"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TLS.SelfSignedDir != "/custom/certs" {
		t.Errorf("expected explicit SelfSignedDir /custom/certs, got %q", cfg.TLS.SelfSignedDir)
	}

	if cfg.TLS.ACME.StorageDir != "/data/tls/acme" {
		t.Errorf("expected derived ACME StorageDir /data/tls/acme, got %q", cfg.TLS.ACME.StorageDir)
	}
}

func TestLoad_TLSDir_EmptyString_Fails(t *testing.T) {
	// Clear ambient env override so the empty-tls_dir validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"

[tls]
tls_dir = ""
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to fail when tls_dir is empty string")
	}

	if !strings.Contains(err.Error(), "tls.tls_dir is set but empty") {
		t.Errorf("expected error about tls_dir empty, got %v", err)
	}
}

func TestLoad_TLSDir_WhitespaceOnly_Fails(t *testing.T) {
	// Clear ambient env override so the whitespace-tls_dir validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"

[tls]
tls_dir = "   "
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to fail when tls_dir is whitespace only")
	}

	if !strings.Contains(err.Error(), "tls.tls_dir is set but empty") {
		t.Errorf("expected error about tls_dir empty, got %v", err)
	}
}

func TestLoad_TLSRootCAFile_Valid(t *testing.T) {
	// Clear ambient env override so the TLS root CA load is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()

	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"), 0644); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"

[outbound_http]
tls_root_ca_file = "` + caFile + `"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.OutboundHTTP.TLSRootCAFile != caFile {
		t.Errorf("expected TLSRootCAFile %q, got %q", caFile, cfg.OutboundHTTP.TLSRootCAFile)
	}
}

func TestLoad_TLSRootCAFile_Missing_Fails(t *testing.T) {
	// Clear ambient env override so the missing-CA validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"

[outbound_http]
tls_root_ca_file = "/nonexistent/ca.pem"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to fail when tls_root_ca_file path does not exist")
	}

	if !strings.Contains(err.Error(), "tls_root_ca_file") {
		t.Errorf("expected error to mention tls_root_ca_file, got %v", err)
	}
}

func TestLoad_TLSRootCADir_NotDirectory_Fails(t *testing.T) {
	// Clear ambient env override so the not-a-dir validation path is deterministic.
	t.Setenv("OCM_CONFIG_OUTBOUND_HTTP_USE_ENV_FALLBACK", "")
	dir := t.TempDir()

	filePath := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	configPath := filepath.Join(dir, "config.toml")

	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"

[outbound_http]
tls_root_ca_dir = "` + filePath + `"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err := Load(LoaderOptions{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected Load to fail when tls_root_ca_dir path is not a directory")
	}

	if !strings.Contains(err.Error(), "tls_root_ca_dir") {
		t.Errorf("expected error to mention tls_root_ca_dir, got %v", err)
	}
}
