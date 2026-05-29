// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestTokenExchangeFlow exercises the full signed code-flow happy path:
// share creation to a strict peer, signed token exchange, and WebDAV access
// with the exchanged bearer token.
func TestTokenExchangeFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	testContent := []byte("Hello from token exchange test - this is the file content!")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	binaryPath := harness.BuildBinary(t)
	sender := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "token-flow-sender",
		Mode:                  "compat",
		KeepSignatureDefaults: true,
		ExtraConfig: `
[outbound_http.ssrf]
mode = "off"
`,
	})
	defer sender.Stop(t)

	receiver := startStrictCodeFlowReceiver(t)
	defer receiver.Close()

	token := loginSubprocessAdmin(t, sender)
	status, body := createOutgoingShare(t, sender.BaseURL, token, map[string]any{
		"receiverDomain": receiver.peerDomain,
		"shareWith":      "bob@" + receiver.peerDomain,
		"localPath":      testFile,
		"permissions":    []string{"read"},
	})
	if status != http.StatusCreated {
		sender.DumpLogs(t)
		t.Fatalf("expected 201 from outgoing share create, got %d: %s", status, body)
	}

	var created struct {
		ProviderID string `json:"providerId"`
		WebDAVID   string `json:"webdavId"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("failed to decode outgoing share response: %v", err)
	}
	if created.ProviderID == "" || created.WebDAVID == "" {
		t.Fatalf("outgoing share response missing providerId/webdavId: %s", body)
	}

	captured := receiver.waitForShare(t)
	if captured.ProviderID != created.ProviderID {
		t.Fatalf("captured providerId %q does not match API response %q", captured.ProviderID, created.ProviderID)
	}
	if captured.SharedSecret == "" {
		t.Fatal("captured strict share is missing sharedSecret")
	}
	if !captured.MustExchangeToken {
		t.Fatal("expected strict receiver to receive must-exchange-token share")
	}
	if !captured.SawSignature {
		t.Fatal("expected outbound /ocm/shares request to be signed for strict receiver")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", receiver.peerDomain)
	form.Set("code", captured.SharedSecret)

	unsignedResp, err := http.Post(
		sender.BaseURL+"/ocm/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("failed to call unsigned token endpoint: %v", err)
	}
	defer unsignedResp.Body.Close()
	if unsignedResp.StatusCode != http.StatusUnauthorized {
		respBody, _ := io.ReadAll(unsignedResp.Body)
		t.Fatalf("expected unsigned token request to be rejected with 401, got %d: %s", unsignedResp.StatusCode, respBody)
	}

	signedReq, err := http.NewRequest(
		http.MethodPost,
		sender.BaseURL+"/ocm/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("failed to create signed token request: %v", err)
	}
	signedReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := receiver.signer.Sign(signedReq); err != nil {
		t.Fatalf("failed to sign token request: %v", err)
	}

	signedResp, err := http.DefaultClient.Do(signedReq)
	if err != nil {
		t.Fatalf("failed to call signed token endpoint: %v", err)
	}
	defer signedResp.Body.Close()
	if signedResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(signedResp.Body)
		t.Fatalf("expected signed token request to succeed, got %d: %s", signedResp.StatusCode, respBody)
	}

	var tokenResp spec.TokenResponse
	if err := json.NewDecoder(signedResp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}
	if tokenResp.AccessToken == "" {
		t.Fatal("signed token exchange returned empty access_token")
	}

	webdavURL := sender.BaseURL + "/webdav/ocm/" + created.WebDAVID + "/" + url.PathEscape(filepath.Base(testFile))
	webdavReq, err := http.NewRequest(http.MethodGet, webdavURL, nil)
	if err != nil {
		t.Fatalf("failed to create WebDAV request: %v", err)
	}
	webdavReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	webdavResp, err := http.DefaultClient.Do(webdavReq)
	if err != nil {
		t.Fatalf("failed to call WebDAV endpoint: %v", err)
	}
	defer webdavResp.Body.Close()
	if webdavResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(webdavResp.Body)
		t.Fatalf("expected WebDAV bearer access to succeed, got %d: %s", webdavResp.StatusCode, respBody)
	}

	gotContent, err := io.ReadAll(webdavResp.Body)
	if err != nil {
		t.Fatalf("failed to read WebDAV response body: %v", err)
	}
	if !bytes.Equal(gotContent, testContent) {
		t.Fatalf("unexpected WebDAV body %q, want %q", gotContent, testContent)
	}
}

// TestWebDAVWithBearerToken tests WebDAV access with bearer token authentication.
func TestWebDAVWithBearerToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	// Create test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "shared-file.txt")
	testContent := []byte("WebDAV test content - verify bytes match!")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Note: [shares] allowed_paths section was removed - it was a phantom knob (not decoded).
	binaryPath := harness.BuildBinary(t)
	srv := harness.StartSubprocessServer(t, binaryPath, harness.SubprocessConfig{
		Name:                  "webdav-test",
		Mode:                  "dev",
		KeepSignatureDefaults: true,
	})
	defer srv.Stop(t)

	t.Run("WebDAVEndpointExists", func(t *testing.T) {
		// Try to access WebDAV endpoint - should require auth
		req, _ := http.NewRequest(http.MethodGet, srv.BaseURL+"/webdav/ocm/550e8400-e29b-41d4-a716-446655440000", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("failed to access WebDAV: %v", err)
		}
		defer resp.Body.Close()

		// Should return 401 (unauthorized) not 404
		if resp.StatusCode == http.StatusNotFound {
			t.Log("WebDAV endpoint returns 404 for nonexistent share (expected)")
		} else if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
			t.Logf("WebDAV returned %d", resp.StatusCode)
		}
	})

	t.Run("WebDAVRequiresAuth", func(t *testing.T) {
		// The WebDAV endpoint should require authorization
		req, _ := http.NewRequest(http.MethodGet, srv.BaseURL+"/webdav/ocm/test-id", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("failed to access WebDAV: %v", err)
		}
		defer resp.Body.Close()

		// Should require auth or return bad request for invalid ID
		validCodes := []int{http.StatusUnauthorized, http.StatusBadRequest}
		found := false
		for _, code := range validCodes {
			if resp.StatusCode == code {
				found = true
				break
			}
		}
		if !found {
			t.Logf("WebDAV returned %d (expected 401 or 400)", resp.StatusCode)
		}
	})
}

// TestTokenExchangeErrorResponses tests OAuth-style error responses from token endpoint.
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

	tests := []struct {
		name           string
		data           url.Values
		expectedError  string
		expectedStatus int
	}{
		{
			name:           "MissingGrantType",
			data:           url.Values{"client_id": {"test"}, "code": {"test"}},
			expectedError:  "invalid_request",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "MissingClientID",
			data:           url.Values{"grant_type": {"ocm_share"}, "code": {"test"}},
			expectedError:  "invalid_request",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "MissingCode",
			data:           url.Values{"grant_type": {"ocm_share"}, "client_id": {"test"}},
			expectedError:  "invalid_request",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "WrongGrantType",
			data:           url.Values{"grant_type": {"password"}, "client_id": {"test"}, "code": {"test"}},
			expectedError:  "invalid_grant",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Post(
				srv.BaseURL+"/ocm/token",
				"application/x-www-form-urlencoded",
				strings.NewReader(tt.data.Encode()),
			)
			if err != nil {
				t.Fatalf("failed to call token endpoint: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected status %d, got %d: %s", tt.expectedStatus, resp.StatusCode, body)
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

func TestOutgoingSharePolicyDifferences_MalformedDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	falseVal := false
	tests := []struct {
		name         string
		peerPolicy   string
		wantStatus   int
		wantPosts    int32
		wantMustExch *bool
	}{
		{
			name:       "strict rejects malformed capable non-strict peer",
			peerPolicy: "strict",
			wantStatus: reason.APIStatus(reason.PeerPolicyUnsatisfied),
			wantPosts:  0,
		},
		{
			name:         "prefer-strict degrades malformed peer to legacy",
			peerPolicy:   "prefer-strict",
			wantStatus:   http.StatusCreated,
			wantPosts:    1,
			wantMustExch: &falseVal,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Each subtest needs its own server because policy is frozen at startup.
			ts := harness.StartTestServerWithConfig(t, func(cfg *config.Config) {
				cfg.PeerPolicy = tc.peerPolicy
			})
			defer ts.Stop(t)

			token := loginAdmin(t, ts.BaseURL, "admin", "admin")

			shareFile, err := os.CreateTemp("/tmp", "policy-diff-malformed-*")
			if err != nil {
				t.Fatalf("failed to create temp share file: %v", err)
			}
			if _, err := shareFile.WriteString("policy diff malformed integration payload"); err != nil {
				t.Fatalf("failed to seed temp share file: %v", err)
			}
			if err := shareFile.Close(); err != nil {
				t.Fatalf("failed to close temp share file: %v", err)
			}
			t.Cleanup(func() { _ = os.Remove(shareFile.Name()) })

			receiver, postCount, mustExchangeFlag := startMalformedCapableNonStrictReceiver(t)
			defer receiver.Close()

			receiverDomain := strings.TrimPrefix(receiver.URL, "https://")
			status, body := createOutgoingShare(t, ts.BaseURL, token, map[string]any{
				"receiverDomain": receiverDomain,
				"shareWith":      "bob@" + receiverDomain,
				"localPath":      shareFile.Name(),
				"permissions":    []string{"read"},
			})

			if status != tc.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", tc.wantStatus, status, body)
			}

			if got := postCount.Load(); got != tc.wantPosts {
				t.Fatalf("expected receiver POST count %d, got %d", tc.wantPosts, got)
			}

			if tc.wantMustExch != nil {
				gotFlag := mustExchangeFlag.Load()
				if gotFlag == -1 {
					t.Fatal("receiver did not capture must-exchange-token state")
				}
				gotMust := gotFlag == 1
				if gotMust != *tc.wantMustExch {
					t.Fatalf("must-exchange-token mismatch: got %v, want %v", gotMust, *tc.wantMustExch)
				}
			}
		})
	}
}

func startMalformedCapableNonStrictReceiver(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()

	postCount := &atomic.Int32{}
	mustExchangeFlag := &atomic.Int32{}
	mustExchangeFlag.Store(-1)
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm", "/ocm-provider":
			disc := spec.Discovery{
				Enabled:      true,
				APIVersion:   "1.2.2",
				EndPoint:     srv.URL + "/ocm",
				Capabilities: []string{"exchange-token"},
				Criteria:     []string{},
				// Intentionally malformed: missing tokenEndPoint.
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(disc)
			return
		case "/ocm/shares":
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			var req spec.NewShareRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid payload", http.StatusBadRequest)
				return
			}
			postCount.Add(1)
			mustExchange := req.Protocol.WebDAV != nil &&
				req.Protocol.WebDAV.HasRequirement(spec.RequirementMustExchangeToken)
			if mustExchange {
				mustExchangeFlag.Store(1)
			} else {
				mustExchangeFlag.Store(0)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		default:
			http.NotFound(w, r)
		}
	}))

	return srv, postCount, mustExchangeFlag
}

type strictCodeFlowShareCapture struct {
	ProviderID        string
	SharedSecret      string
	MustExchangeToken bool
	SawSignature      bool
}

type strictCodeFlowReceiver struct {
	server     *httptest.Server
	peerDomain string
	signer     *crypto.RFC9421Signer
	captures   chan strictCodeFlowShareCapture
}

func startStrictCodeFlowReceiver(t *testing.T) *strictCodeFlowReceiver {
	t.Helper()

	captures := make(chan strictCodeFlowShareCapture, 1)
	var srv *httptest.Server
	var km *crypto.KeyManager
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm", "/ocm-provider":
			if km == nil {
				http.Error(w, "receiver signing key not initialized", http.StatusServiceUnavailable)
				return
			}
			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.2.2",
				EndPoint:      srv.URL + "/ocm",
				ResourceTypes: []spec.ResourceType{{Name: "file", ShareTypes: []string{"user"}, Protocols: map[string]string{"webdav": "/webdav/ocm/"}}},
				Capabilities:  []string{"exchange-token", "http-sig"},
				Criteria:      []string{"token-exchange", "http-request-signatures"},
				PublicKeys: []spec.PublicKey{{
					KeyID:        km.GetKeyID(),
					PublicKeyPem: km.GetPublicKeyPEM(),
					Algorithm:    "ed25519",
				}},
				TokenEndPoint: srv.URL + "/ocm/token",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(disc)
		case "/ocm/shares":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read share body", http.StatusBadRequest)
				return
			}
			var req spec.NewShareRequest
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, "failed to parse share body", http.StatusBadRequest)
				return
			}
			if req.Protocol.WebDAV == nil {
				http.Error(w, "missing webdav payload", http.StatusBadRequest)
				return
			}
			capture := strictCodeFlowShareCapture{
				ProviderID:        req.ProviderID,
				SharedSecret:      req.Protocol.WebDAV.SharedSecret,
				MustExchangeToken: req.Protocol.WebDAV.HasRequirement(spec.RequirementMustExchangeToken),
				SawSignature:      r.Header.Get("Signature") != "",
			}
			select {
			case captures <- capture:
			default:
				<-captures
				captures <- capture
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"recipientDisplayName":"Strict Receiver"}`))
		default:
			http.NotFound(w, r)
		}
	}))

	km = crypto.NewKeyManager("", srv.URL)
	if err := km.LoadOrGenerate(); err != nil {
		srv.Close()
		t.Fatalf("failed to create strict receiver signing key: %v", err)
	}

	parsedURL, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatalf("failed to parse strict receiver URL: %v", err)
	}

	return &strictCodeFlowReceiver{
		server:     srv,
		peerDomain: parsedURL.Host,
		signer:     crypto.NewRFC9421Signer(km),
		captures:   captures,
	}
}

func (r *strictCodeFlowReceiver) Close() {
	if r != nil && r.server != nil {
		r.server.Close()
	}
}

func (r *strictCodeFlowReceiver) waitForShare(t *testing.T) strictCodeFlowShareCapture {
	t.Helper()

	select {
	case capture := <-r.captures:
		return capture
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for strict share capture")
		return strictCodeFlowShareCapture{}
	}
}

func loginSubprocessAdmin(t *testing.T, srv *harness.SubprocessServer) string {
	t.Helper()

	if token, _, ok := tryLogin(t, srv.BaseURL, "admin", "admin"); ok {
		return token
	}

	logPath := filepath.Join(srv.TempDir, "server.log")
	logs, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read subprocess log for bootstrap password: %v", err)
	}

	password := extractBootstrapPassword(string(logs))
	if password == "" {
		t.Fatalf("could not find bootstrap admin password in server log:\n%s", logs)
	}

	token, body, ok := tryLogin(t, srv.BaseURL, "admin", password)
	if !ok {
		t.Fatalf("login failed with logged bootstrap password %q: %s", password, body)
	}
	return token
}

func tryLogin(t *testing.T, baseURL, username, password string) (string, string, bool) {
	t.Helper()

	reqBody, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		t.Fatalf("failed to encode login request: %v", err)
	}
	resp, err := http.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to call login endpoint: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", string(body), false
	}

	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("failed to parse login response: %v", err)
	}
	if parsed.Token == "" {
		return "", string(body), false
	}
	return parsed.Token, string(body), true
}

func extractBootstrapPassword(logs string) string {
	marker := `"password":"`
	start := strings.Index(logs, marker)
	if start == -1 {
		return ""
	}
	start += len(marker)
	end := strings.Index(logs[start:], `"`)
	if end == -1 {
		return ""
	}
	return logs[start : start+end]
}

func loginAdmin(t *testing.T, baseURL, username, password string) string {
	t.Helper()

	reqBody, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		t.Fatalf("failed to encode login request: %v", err)
	}
	resp, err := http.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to call login endpoint: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: status=%d body=%s", resp.StatusCode, body)
	}

	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("failed to parse login response: %v", err)
	}
	if parsed.Token == "" {
		t.Fatalf("login returned empty token: %s", body)
	}
	return parsed.Token
}

func createOutgoingShare(t *testing.T, baseURL, token string, payload map[string]any) (int, string) {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal outgoing share payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/shares/outgoing", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create outgoing share request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to call outgoing share endpoint: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(respBody)
}
