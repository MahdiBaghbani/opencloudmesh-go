// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestFederationsEndpoint verifies /ocm-aux/federations returns federation info
// when the server is configured with federation enabled.
func TestFederationsEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	// Minimal K2 JSON federation config - just enough to be valid and appear in the response
	federationJSON := `{
		"federation_id": "test-federation-001",
		"enabled": true,
		"enforce_membership": false,
		"directory_services": [],
		"keys": []
	}`

	// TOML config to enable federation and reference the JSON file
	// The path uses a relative reference that will be resolved against tempDir
	extraConfig := `
[federation]
enabled = true
config_paths = ["federation.json"]

[federation.policy]
global_enforce = false

[federation.membership_cache]
ttl_seconds = 300
max_stale_seconds = 600
`

	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "federation-test",
		Mode: "dev",
		ExtraFiles: map[string]string{
			"federation.json": federationJSON,
		},
		ExtraConfig: extraConfig,
	})
	defer srv.Stop(t)

	// GET /ocm-aux/federations
	resp, err := http.Get(srv.BaseURL + "/ocm-aux/federations")
	if err != nil {
		srv.DumpLogs(t)
		t.Fatalf("failed to get /ocm-aux/federations: %v", err)
	}
	defer resp.Body.Close()

	// Assert 200 OK
	if resp.StatusCode != http.StatusOK {
		srv.DumpLogs(t)
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Decode response
	var fedResp struct {
		Federations []struct {
			FederationID      string `json:"federation_id"`
			Enabled           bool   `json:"enabled"`
			EnforceMembership bool   `json:"enforce_membership"`
		} `json:"federations"`
		Members []struct {
			Host string `json:"host"`
			Name string `json:"name"`
		} `json:"members"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&fedResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Assert federations array is non-empty
	if len(fedResp.Federations) == 0 {
		srv.DumpLogs(t)
		t.Fatal("expected non-empty federations array")
	}

	// Assert the test federation is present
	found := false
	for _, fed := range fedResp.Federations {
		if fed.FederationID == "test-federation-001" {
			found = true
			if !fed.Enabled {
				t.Errorf("expected federation to be enabled")
			}
			t.Logf("federation found: id=%s enabled=%v enforce_membership=%v",
				fed.FederationID, fed.Enabled, fed.EnforceMembership)
			break
		}
	}
	if !found {
		t.Errorf("expected to find federation 'test-federation-001' in response, got: %+v", fedResp.Federations)
	}

	// Members can be empty (no DS configured), that's OK
	t.Logf("federation endpoint returned %d federation(s) and %d member(s)",
		len(fedResp.Federations), len(fedResp.Members))
}

// TestFederationsEndpointWithoutFederation verifies /ocm-aux/federations works
// when federation is not enabled (returns empty arrays).
func TestFederationsEndpointWithoutFederation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "no-federation-test",
		Mode: "dev",
		// No ExtraFiles, no federation config - defaults to disabled
	})
	defer srv.Stop(t)

	// GET /ocm-aux/federations
	resp, err := http.Get(srv.BaseURL + "/ocm-aux/federations")
	if err != nil {
		srv.DumpLogs(t)
		t.Fatalf("failed to get /ocm-aux/federations: %v", err)
	}
	defer resp.Body.Close()

	// Assert 200 OK (endpoint exists even without federation)
	if resp.StatusCode != http.StatusOK {
		srv.DumpLogs(t)
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Decode response
	var fedResp struct {
		Federations []interface{} `json:"federations"`
		Members     []interface{} `json:"members"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&fedResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Both arrays should be empty when federation is disabled
	if len(fedResp.Federations) != 0 {
		t.Errorf("expected empty federations array, got %d items", len(fedResp.Federations))
	}
	if len(fedResp.Members) != 0 {
		t.Errorf("expected empty members array, got %d items", len(fedResp.Members))
	}

	t.Log("federation endpoint correctly returns empty arrays when federation is disabled")
}
