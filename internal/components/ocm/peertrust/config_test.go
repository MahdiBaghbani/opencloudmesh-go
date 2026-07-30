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
	defer os.RemoveAll(tempDir) //nolint:errcheck // test cleanup: temp path removal

	path := filepath.Join(tempDir, "trust-group.json")

	data := `{"trustGroupId":"sciencemesh-prod","enabled":true,"enforceMembership":false,"directoryServices":[],"keys":[]}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
		t.Fatalf("failed to write file: %v", err)
	}

	cfg, err := LoadTrustGroupConfig(path)
	if err != nil {
		t.Fatalf("LoadTrustGroupConfig() error = %v", err)
	}

	if cfg.TrustGroupID != "sciencemesh-prod" {
		t.Errorf("expected trustGroupId 'sciencemesh-prod', got %q", cfg.TrustGroupID)
	}
}

func TestLoadTrustGroupConfig_FederationIDUnknownField_Fails(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tg-config-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir) //nolint:errcheck // test cleanup: temp path removal

	path := filepath.Join(tempDir, "trust-group.json")

	data := `{"federation_id":"test-group","enabled":true,"directoryServices":[],"keys":[]}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
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
	defer os.RemoveAll(tempDir) //nolint:errcheck // test cleanup: temp path removal

	path := filepath.Join(tempDir, "trust-group.json")

	data := `{"trustGroupId":"test","enabled":true,"directoryServices":[],"keys":[]}{"extra":"trailing"}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
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
	defer os.RemoveAll(tempDir) //nolint:errcheck // test cleanup: temp path removal

	path := filepath.Join(tempDir, "trust-group.json")

	data := `{"trustGroupId":"test","enabled":true,"directoryServices":[{"url":"https://ds.example.com","enabled":true,"verification":"bogus"}],"keys":[]}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
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
	defer os.RemoveAll(tempDir) //nolint:errcheck // test cleanup: temp path removal

	path := filepath.Join(tempDir, "trust-group.json")

	data := `{"trustGroupId":"test","enabled":true,"directoryServices":[{"url":"https://ds.example.com","enabled":true,"verification":"optional"}],"keys":[]}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
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

func TestPolicyConfig_HasDenylist(t *testing.T) {
	if (&PolicyConfig{}).HasDenylist() {
		t.Error("empty PolicyConfig should not HasDenylist")
	}

	if !(&PolicyConfig{DenyList: []string{"blocked.example.com"}}).HasDenylist() {
		t.Error("nonempty DenyList should HasDenylist")
	}
}

func TestPolicyConfig_HasAllowlist(t *testing.T) {
	if (&PolicyConfig{}).HasAllowlist() {
		t.Error("empty PolicyConfig should not HasAllowlist")
	}

	if !(&PolicyConfig{AllowList: []string{"trusted.example.com"}}).HasAllowlist() {
		t.Error("nonempty AllowList should HasAllowlist")
	}
}
