// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestFederationsEndpoint verifies /ocm-aux/federations returns a valid JSON array
// when the server is configured with peer trust enabled (but no directory services).
// With no directory services configured, the response is an empty array.
// Detailed response shape testing is in internal/components/ocmaux/handler_test.go.
func TestFederationsEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	// K2 JSON config: trust group enabled but no directory services to fetch from
	federationJSON := `{
		"federation_id": "test-federation-001",
		"enabled": true,
		"enforce_membership": false,
		"directory_services": [],
		"keys": []
	}`

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

	if resp.StatusCode != http.StatusOK {
		srv.DumpLogs(t)
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Response is now a top-level JSON array (Reva-aligned strict break)
	var result []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("expected JSON array response: %v", err)
	}

	// With no directory services configured, the array is empty (no listings to show)
	t.Logf("federation endpoint returned %d federation entries (expected 0 with no DS configured)", len(result))
}

// TestFederationsEndpointWithoutFederation verifies /ocm-aux/federations works
// when peer trust is not enabled (returns empty JSON array).
func TestFederationsEndpointWithoutFederation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "no-federation-test",
		Mode: "dev",
	})
	defer srv.Stop(t)

	resp, err := http.Get(srv.BaseURL + "/ocm-aux/federations")
	if err != nil {
		srv.DumpLogs(t)
		t.Fatalf("failed to get /ocm-aux/federations: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		srv.DumpLogs(t)
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// Response is a top-level JSON array
	var result []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("expected JSON array response: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected empty array when peer trust is disabled, got %d items", len(result))
	}

	t.Log("federation endpoint correctly returns empty array when peer trust is disabled")
}
