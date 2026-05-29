package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_TLSDir_Absent_NoChange(t *testing.T) {
	// No tls_dir in TOML; paths stay at preset defaults
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TLS.TLSDir != "" {
		t.Errorf("expected TLSDir empty when absent, got %q", cfg.TLS.TLSDir)
	}
	if cfg.TLS.SelfSignedDir != ".ocm/certs" {
		t.Errorf("expected SelfSignedDir .ocm/certs from preset, got %q", cfg.TLS.SelfSignedDir)
	}
	if cfg.TLS.ACME.StorageDir != ".ocm/acme" {
		t.Errorf("expected ACME StorageDir .ocm/acme from preset, got %q", cfg.TLS.ACME.StorageDir)
	}
	if cfg.Signature.KeyPath != ".ocm/keys/signing.pem" {
		t.Errorf("expected Signature KeyPath .ocm/keys/signing.pem from preset, got %q", cfg.Signature.KeyPath)
	}
}

func TestLoad_TLSDir_NotInTOML_NoDerivation(t *testing.T) {
	// Even with [tls] present, derivation must not run unless tls_dir key is present.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"

[tls]
mode = "selfsigned"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TLS.TLSDir != "" {
		t.Errorf("expected TLSDir empty when tls_dir key is absent, got %q", cfg.TLS.TLSDir)
	}
	if cfg.TLS.SelfSignedDir != ".ocm/certs" {
		t.Errorf("expected preset SelfSignedDir .ocm/certs, got %q", cfg.TLS.SelfSignedDir)
	}
	if cfg.TLS.ACME.StorageDir != ".ocm/acme" {
		t.Errorf("expected preset ACME StorageDir .ocm/acme, got %q", cfg.TLS.ACME.StorageDir)
	}
	if cfg.Signature.KeyPath != ".ocm/keys/signing.pem" {
		t.Errorf("expected preset Signature KeyPath .ocm/keys/signing.pem, got %q", cfg.Signature.KeyPath)
	}
}

func TestLoad_TLSDir_Present_DerivesDefaults(t *testing.T) {
	// tls_dir set; derives self_signed_dir, acme.storage_dir, signature.key_path
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	tomlContent := `mode = "strict"
public_origin = "https://localhost:9200"

[tls]
tls_dir = "/data/tls"
`
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := Load(LoaderOptions{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.TLS.TLSDir != "/data/tls" {
		t.Errorf("expected TLSDir /data/tls, got %q", cfg.TLS.TLSDir)
	}
	if cfg.TLS.SelfSignedDir != "/data/tls/certs" {
		t.Errorf("expected SelfSignedDir /data/tls/certs, got %q", cfg.TLS.SelfSignedDir)
	}
	if cfg.TLS.ACME.StorageDir != "/data/tls/acme" {
		t.Errorf("expected ACME StorageDir /data/tls/acme, got %q", cfg.TLS.ACME.StorageDir)
	}
	if cfg.Signature.KeyPath != "/data/tls/keys/signing.pem" {
		t.Errorf("expected Signature KeyPath /data/tls/keys/signing.pem, got %q", cfg.Signature.KeyPath)
	}
}

func TestLoad_TLSDir_ExplicitOverride(t *testing.T) {
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
