package architecture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
	"gopkg.in/yaml.v3"
)

func TestSpecPinPresent(t *testing.T) {
	root := modroot.ModuleRoot(t)
	vendorDir := filepath.Join(root, "internal", "components", "ocm", "spec", "vendor")
	pinPath := filepath.Join(vendorDir, "pin.json")
	specPath := filepath.Join(vendorDir, "spec.yaml")

	if _, err := os.Stat(pinPath); err != nil {
		t.Fatalf("vendored pin.json not found: %v", err)
	}
	if _, err := os.Stat(specPath); err != nil {
		t.Fatalf("vendored spec.yaml not found: %v", err)
	}

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

	if pin.Commit != "f9a704f63477134701c0b58b29bb6b98949361dc" {
		t.Errorf("pin.json commit = %q, want f9a704f63477134701c0b58b29bb6b98949361dc", pin.Commit)
	}
	if pin.Version != "v1.4.0" {
		t.Errorf("pin.json version = %q, want v1.4.0", pin.Version)
	}

	specData, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("failed to read spec.yaml: %v", err)
	}

	var spec struct {
		Info struct {
			Version string `yaml:"version"`
		} `yaml:"info"`
	}
	if err := yaml.Unmarshal(specData, &spec); err != nil {
		t.Fatalf("failed to parse spec.yaml: %v", err)
	}
	if spec.Info.Version != "1.4.0" {
		t.Errorf("spec.yaml info.version = %q, want 1.4.0", spec.Info.Version)
	}
}

func TestRuntimeAPIVersionPinMatchesVendoredSpec(t *testing.T) {
	root := modroot.ModuleRoot(t)
	specPath := filepath.Join(root, "internal", "components", "ocm", "spec", "vendor", "spec.yaml")

	specData, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("failed to read spec.yaml: %v", err)
	}

	var vendored struct {
		Info struct {
			Version string `yaml:"version"`
		} `yaml:"info"`
	}
	if err := yaml.Unmarshal(specData, &vendored); err != nil {
		t.Fatalf("failed to parse spec.yaml: %v", err)
	}

	if spec.APIVersionPin != vendored.Info.Version {
		t.Errorf("spec.APIVersionPin = %q, want vendored spec.yaml info.version %q",
			spec.APIVersionPin, vendored.Info.Version)
	}
}
