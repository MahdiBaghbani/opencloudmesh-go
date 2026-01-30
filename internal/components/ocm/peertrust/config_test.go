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

func TestLoadTrustGroupConfig_FederationIDStrictBreak(t *testing.T) {
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
		t.Fatal("expected error for deprecated federation_id key")
	}
	if !strings.Contains(err.Error(), "has been renamed to 'trust_group_id'") {
		t.Errorf("expected strict-break migration message, got: %v", err)
	}
}

func TestLoadTrustGroupConfig_BothKeysStrictBreak(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tg-config-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	path := filepath.Join(tempDir, "trust-group.json")
	data := `{"federation_id":"old","trust_group_id":"new","enabled":true,"directory_services":[],"keys":[]}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err = LoadTrustGroupConfig(path)
	if err == nil {
		t.Fatal("expected error when both federation_id and trust_group_id are present")
	}
	if !strings.Contains(err.Error(), "contains both 'federation_id' and 'trust_group_id'") {
		t.Errorf("expected both-keys error message, got: %v", err)
	}
}

func TestLoadTrustGroupConfig_MissingFile(t *testing.T) {
	_, err := LoadTrustGroupConfig("/nonexistent/path/trust-group.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
