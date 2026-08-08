// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// OCM conformance is measured against IETF-OCM.md (the prose Internet-Draft),
// not the vendored OpenAPI snapshot. Normative SSOT:
// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md
//
// spec.yaml is a derived snapshot pinned for schema stability and may lag the
// prose spec, including http-sig applicability for /request-share and
// /invite-accepted. Tests here assert vendored snapshot integrity (pin.json
// and spec.yaml exist and agree with spec.APIVersionPin), not normative
// behavior.
package architecture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

func TestSpecPinPresent(t *testing.T) {
	t.Parallel()
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
	if uerr := json.Unmarshal(data, &pin); uerr != nil {
		t.Fatalf("failed to parse pin.json: %v", uerr)
	}

	if pin.Commit != "6a0586183cbef10ecae9dedc42561806447eb2f5" {
		t.Errorf("pin.json commit = %q, want 6a0586183cbef10ecae9dedc42561806447eb2f5", pin.Commit)
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
	t.Parallel()
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
