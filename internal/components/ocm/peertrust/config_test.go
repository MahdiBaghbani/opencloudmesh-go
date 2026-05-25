package peertrust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadTrustGroupConfig_ValidTrustGroupID(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tg-config-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	path := filepath.Join(tempDir, "trust-group.json")
	data := `{"trust_group_id":"sciencemesh-prod","enabled":true,"enforce_membership":false,"directory_services":[],"keys":[]}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	cfg, err := LoadTrustGroupConfig(path)
	if err != nil {
		t.Fatalf("LoadTrustGroupConfig() error = %v", err)
	}
	if cfg.TrustGroupID != "sciencemesh-prod" {
		t.Errorf("expected trust_group_id 'sciencemesh-prod', got %q", cfg.TrustGroupID)
	}
}

func TestLoadTrustGroupConfig_FederationIDUnknownField_Fails(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tg-config-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	path := filepath.Join(tempDir, "trust-group.json")
	data := `{"federation_id":"test-group","enabled":true,"directory_services":[],"keys":[]}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err = LoadTrustGroupConfig(path)
	if err == nil {
		t.Fatal("expected error for unknown federation_id key")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("expected unknown-field error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "federation_id") {
		t.Errorf("expected error mentioning federation_id, got: %v", err)
	}
}

func TestLoadTrustGroupConfig_TrailingJSONRejected(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tg-config-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	path := filepath.Join(tempDir, "trust-group.json")
	data := `{"trust_group_id":"test","enabled":true,"directory_services":[],"keys":[]}{"extra":"trailing"}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err = LoadTrustGroupConfig(path)
	if err == nil {
		t.Fatal("expected error for trailing JSON content")
	}
	if !strings.Contains(err.Error(), "trailing content") {
		t.Errorf("expected trailing-content error, got: %v", err)
	}
}

func TestLoadTrustGroupConfig_MissingFile(t *testing.T) {
	_, err := LoadTrustGroupConfig("/nonexistent/path/trust-group.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadTrustGroupConfig_InvalidVerification(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tg-config-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	path := filepath.Join(tempDir, "trust-group.json")
	data := `{"trust_group_id":"test","enabled":true,"directory_services":[{"url":"https://ds.example.com","enabled":true,"verification":"bogus"}],"keys":[]}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err = LoadTrustGroupConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid verification value")
	}
	if !strings.Contains(err.Error(), "invalid verification value") {
		t.Errorf("expected invalid verification error, got: %v", err)
	}
}

func TestLoadTrustGroupConfig_ValidVerification(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tg-config-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	path := filepath.Join(tempDir, "trust-group.json")
	data := `{"trust_group_id":"test","enabled":true,"directory_services":[{"url":"https://ds.example.com","enabled":true,"verification":"optional"}],"keys":[]}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	cfg, err := LoadTrustGroupConfig(path)
	if err != nil {
		t.Fatalf("LoadTrustGroupConfig() error = %v", err)
	}
	if cfg.DirectoryServices[0].Verification != "optional" {
		t.Errorf("expected verification 'optional', got %q", cfg.DirectoryServices[0].Verification)
	}
}
