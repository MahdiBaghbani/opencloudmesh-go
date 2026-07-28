// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestDevModeCanonicalPolicy exercises canonical policy under dev mode:
// bounded route-policy governance with a strict global OCM posture.
func TestDevModeCanonicalPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)

	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name: "dev-policy",
		Mode: "dev",
		ExtraConfig: `
[outbound_http.ssrf]
mode = "off"
`,
	})
	defer srv.Stop(t)

	t.Run("DiscoveryAdvertisesExchangeToken", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.BaseURL + "/.well-known/ocm")
		if err != nil {
			srv.DumpLogs(t)
			t.Fatalf("failed to get discovery: %v", err)
		}
		//nolint:errcheck // test cleanup: response body close
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discovery returned %d", resp.StatusCode)
		}

		var disc struct {
			Enabled       bool     `json:"enabled"`
			Capabilities  []string `json:"capabilities"`
			Criteria      []string `json:"criteria"`
			TokenEndPoint string   `json:"tokenEndPoint"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
			t.Fatalf("failed to decode discovery: %v", err)
		}

		if !disc.Enabled {
			t.Fatal("discovery should be enabled in dev mode")
		}

		hasExchangeToken := false

		for _, cap := range disc.Capabilities {
			if strings.Contains(cap, "exchange-token") {
				hasExchangeToken = true
			}
		}

		if !hasExchangeToken {
			t.Error("dev mode should advertise exchange-token capability")
		}

		if disc.TokenEndPoint == "" {
			t.Error("dev mode should advertise tokenEndPoint")
		}

		hasHTTPReqSigs := false

		for _, criterion := range disc.Criteria {
			if criterion == spec.CriteriaMustUseHTTPSig {
				hasHTTPReqSigs = true
				break
			}
		}

		if !hasHTTPReqSigs {
			t.Error("dev mode should advertise signature criterion")
		}
	})

	t.Run("HealthEndpoint", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.BaseURL + "/api/healthz")
		if err != nil {
			t.Fatalf("health check failed: %v", err)
		}
		//nolint:errcheck // test cleanup: response body close
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("health endpoint returned %d", resp.StatusCode)
		}
	})

	t.Run("TokenEndpointRejectsInvalidGrant", func(t *testing.T) {
		peer := startStrictCodeFlowReceiver(t)
		defer peer.Close()

		data := url.Values{}
		data.Set("grant_type", "invalid_type")
		data.Set("client_id", peer.peerDomain)
		data.Set("code", "some-secret")

		req, err := http.NewRequest(
			http.MethodPost,
			srv.BaseURL+"/ocm/token",
			strings.NewReader(data.Encode()),
		)
		if err != nil {
			t.Fatalf("failed to build token request: %v", err)
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		if err := peer.signer.Sign(req); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
			t.Fatalf("failed to sign token request: %v", err)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("failed to call token endpoint: %v", err)
		}
		//nolint:errcheck // test cleanup: response body close
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response body: %v", err)
			}

			t.Fatalf("expected 400 for invalid grant_type, got %d: %s", resp.StatusCode, body)
		}

		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			t.Fatalf("failed to decode error: %v", err)
		}

		if errResp.Error != "unsupported_grant_type" {
			t.Errorf("expected error=unsupported_grant_type, got %q", errResp.Error)
		}
	})
}

// TestDiscoverySignatureCriteriaMatrixByPosture verifies the discovery
// signature criterion tracks the resolved signature posture across modes.
func TestDiscoverySignatureCriteriaMatrixByPosture(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	tests := []struct {
		name            string
		mode            string
		extraConfig     string
		wantHTTPReqSigs bool
	}{
		{
			name:            "strict advertises signature criterion",
			mode:            "strict",
			wantHTTPReqSigs: true,
		},
		{
			name:            "dev advertises signature criterion",
			mode:            "dev",
			wantHTTPReqSigs: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
				Name:        "criteria-matrix-" + tt.mode,
				Mode:        tt.mode,
				ExtraConfig: tt.extraConfig,
			})
			defer srv.Stop(t)

			resp, err := srv.Client().Get(srv.BaseURL + "/.well-known/ocm")
			if err != nil {
				srv.DumpLogs(t)
				t.Fatalf("failed to get discovery: %v", err)
			}
			//nolint:errcheck // test cleanup: response body close
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("discovery returned %d", resp.StatusCode)
			}

			var disc struct {
				Enabled  bool     `json:"enabled"`
				Criteria []string `json:"criteria"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
				t.Fatalf("failed to decode discovery: %v", err)
			}

			if !disc.Enabled {
				t.Fatalf("discovery should be enabled in %s mode", tt.mode)
			}

			hasHTTPReqSigs := false

			for _, criterion := range disc.Criteria {
				if criterion == spec.CriteriaMustUseHTTPSig {
					hasHTTPReqSigs = true
					break
				}
			}

			if hasHTTPReqSigs != tt.wantHTTPReqSigs {
				t.Fatalf(
					"mode %s criteria mismatch: has signature criterion=%v, want %v (criteria=%v)",
					tt.mode,
					hasHTTPReqSigs,
					tt.wantHTTPReqSigs,
					disc.Criteria,
				)
			}
		})
	}
}
