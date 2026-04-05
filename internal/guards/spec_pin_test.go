package guards

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestSpecPinPresent verifies that the vendored OCM-API spec pin exists
// and matches the expected commit and version locked by the plan.
func TestSpecPinPresent(t *testing.T) {
	repoRoot := findRepoRoot(t)
	pinPath := filepath.Join(repoRoot, "internal", "components", "ocm", "spec", "vendor", "pin.json")

	data, err := os.ReadFile(pinPath)
	if err != nil {
		t.Fatalf("failed to read pin.json: %v", err)
	}

	var pin struct {
		Repo    string `json:"repo"`
		Commit  string `json:"commit"`
		Version string `json:"version"`
		File    string `json:"file"`
	}
	if err := json.Unmarshal(data, &pin); err != nil {
		t.Fatalf("failed to parse pin.json: %v", err)
	}

	if pin.Commit != "a2b8bacd4590ff201a06883330b67636e99c4f5b" {
		t.Errorf("pin.json commit = %q, want a2b8bacd4590ff201a06883330b67636e99c4f5b", pin.Commit)
	}
	if pin.Version != "develop" {
		t.Errorf("pin.json version = %q, want develop", pin.Version)
	}

	// Verify the spec file itself exists
	specPath := filepath.Join(repoRoot, "internal", "components", "ocm", "spec", "vendor", "spec.yaml")
	if _, err := os.Stat(specPath); err != nil {
		t.Fatalf("vendored spec.yaml not found: %v", err)
	}
}
