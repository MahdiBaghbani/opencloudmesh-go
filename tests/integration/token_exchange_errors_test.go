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

	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestTokenExchangeErrorResponses tests OAuth-style error responses from the
// token endpoint under real strict inbound signature posture. Requests are
// signed by a peer that advertises JWKS so middleware verification succeeds
// before handler validation runs.
func TestTokenExchangeErrorResponses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "token-errors",
		Mode:                  "dev",
		KeepSignatureDefaults: true,
	})
	defer srv.Stop(t)

	peer := startStrictCodeFlowReceiver(t)
	defer peer.Close()

	tests := []struct {
		name           string
		data           url.Values
		expectedError  string
		expectedStatus int
		// middlewarePlain rejects before the OAuth handler (no JSON body).
		middlewarePlain string
	}{
		{
			name:           "MissingGrantType",
			data:           url.Values{"client_id": {peer.peerDomain}, "code": {"test"}},
			expectedError:  "invalid_request",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:            "MissingClientID",
			data:            url.Values{"grant_type": {"authorization_code"}, "code": {"test"}},
			expectedStatus:  http.StatusBadRequest,
			middlewarePlain: "invalid declared peer",
		},
		{
			name:           "MissingCode",
			data:           url.Values{"grant_type": {"authorization_code"}, "client_id": {peer.peerDomain}},
			expectedError:  "invalid_request",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "WrongGrantType",
			data: url.Values{
				"grant_type": {"password"},
				"client_id":  {peer.peerDomain},
				"code":       {"test"},
			},
			expectedError:  "unsupported_grant_type",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := tt.data.Encode()
			req, err := http.NewRequest(
				http.MethodPost,
				srv.BaseURL+"/ocm/token",
				strings.NewReader(body),
			)
			if err != nil {
				t.Fatalf("failed to build token request: %v", err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if err := peer.signer.Sign(req); err != nil {
				t.Fatalf("failed to sign token request: %v", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("failed to call token endpoint: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				respBody, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected status %d, got %d: %s", tt.expectedStatus, resp.StatusCode, respBody)
			}

			if tt.middlewarePlain != "" {
				respBody, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("failed to read middleware body: %v", err)
				}
				if got := strings.TrimSpace(string(respBody)); got != tt.middlewarePlain {
					t.Fatalf("expected middleware body %q, got %q", tt.middlewarePlain, got)
				}
				return
			}

			var errResp struct {
				Error string `json:"error"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
				t.Fatalf("failed to decode error response: %v", err)
			}

			if errResp.Error != tt.expectedError {
				t.Errorf("expected error=%q, got %q", tt.expectedError, errResp.Error)
			}
		})
	}
}
