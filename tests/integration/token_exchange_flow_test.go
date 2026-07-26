// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
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
		Name: "token-flow-sender",
		Mode: "dev",
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
		"receiverDomain": receiver.peerBaseURL,
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

	if len(captured.Requirements) != 1 || captured.Requirements[0] != spec.RequirementMustExchangeToken {
		t.Fatalf("expected requirements [%s], got %v", spec.RequirementMustExchangeToken, captured.Requirements)
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

func TestIETFHarness_WiresCryptoDeps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := harness.StartTestServerWithIETFConfig(t, nil)
	defer ts.Stop(t)

	if ts.Deps.KeyManager == nil {
		t.Fatal("KeyManager must be wired when IETF harness opts are used")
	}

	if ts.Deps.Signer == nil {
		t.Fatal("Signer must be wired when IETF harness opts are used")
	}

	if ts.Deps.SignatureMiddleware == nil {
		t.Fatal("SignatureMiddleware must be wired when IETF harness opts are used")
	}

	if ts.Config.Signature.Label != config.DefaultSignatureLabel {
		t.Fatalf("signature label = %q, want %q", ts.Config.Signature.Label, config.DefaultSignatureLabel)
	}
}

func TestIETFTwoInstance_JWKSRouteAndSignedTokenExchange(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	provider := harness.StartTestServerWithIETFConfig(t, nil)
	client := harness.StartTestServerWithIETFConfig(t, nil)

	clientHost := hostFromBaseURL(t, client.BaseURL)
	sharedSecret := "ietf-signed-token-secret"

	assertClientJWKS(t, client, clientHost)
	assertProviderDiscoveryUsesOCMLabel(t, provider)

	ctx := context.Background()
	if err := provider.Deps.OutgoingShareRepo.Create(ctx, &outgoing.OutgoingShare{
		ShareID:      "share-ietf-1",
		ProviderID:   "provider-ietf-1",
		WebDAVID:     "webdav-ietf-1",
		SharedSecret: sharedSecret,
		ReceiverHost: clientHost,
		CreatedAt:    time.Now(),
	}); err != nil {
		t.Fatalf("seed outgoing share: %v", err)
	}

	unsignedStatus := postTokenExchange(t, provider.BaseURL, clientHost, sharedSecret, nil)
	if unsignedStatus != http.StatusUnauthorized {
		t.Fatalf("unsigned token exchange = %d, want 401", unsignedStatus)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientHost)
	form.Set("code", sharedSecret)
	body := []byte(form.Encode())

	signedReq, err := http.NewRequest(http.MethodPost, provider.BaseURL+"/ocm/token", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create signed token request: %v", err)
	}

	signedReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := client.Deps.Signer.SignRequest(signedReq, body); err != nil {
		t.Fatalf("sign token request: %v", err)
	}

	sigInput := signedReq.Header.Get("Signature-Input")
	if !strings.HasPrefix(sigInput, "ocm=") {
		t.Fatalf("Signature-Input = %q, want ocm= prefix", sigInput)
	}

	if signedReq.Header.Get("Signature") == "" {
		t.Fatal("expected Signature header on signed token request")
	}

	signedResp, err := http.DefaultClient.Do(signedReq)
	if err != nil {
		t.Fatalf("signed token exchange request failed: %v", err)
	}
	defer signedResp.Body.Close()

	if signedResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(signedResp.Body)
		t.Fatalf("signed token exchange = %d, want 200: %s", signedResp.StatusCode, respBody)
	}

	var tokenResp token.TokenResponse
	if err := json.NewDecoder(signedResp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	if tokenResp.AccessToken == "" {
		t.Fatal("signed token exchange returned empty access_token")
	}
}

func assertClientJWKS(t *testing.T, client *harness.TestServer, clientHost string) {
	t.Helper()

	resp, err := http.Get(client.BaseURL + jwks.WellKnownPath)
	if err != nil {
		t.Fatalf("fetch client JWKS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("client JWKS status = %d, want 200: %s", resp.StatusCode, body)
	}

	var set jwks.Set
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatalf("decode client JWKS: %v", err)
	}

	if len(set.Keys) != 1 {
		t.Fatalf("client JWKS keys = %d, want 1", len(set.Keys))
	}

	wantKid := client.Deps.KeyManager.GetKeyID()
	if set.Keys[0].Kid != wantKid {
		t.Fatalf("client JWKS kid = %q, want %q", set.Keys[0].Kid, wantKid)
	}

	if !strings.Contains(wantKid, clientHost) {
		t.Fatalf("keyId %q should reference client host %q", wantKid, clientHost)
	}
}

func assertProviderDiscoveryUsesOCMLabel(t *testing.T, provider *harness.TestServer) {
	t.Helper()

	resp, err := http.Get(provider.BaseURL + "/.well-known/ocm")
	if err != nil {
		t.Fatalf("fetch provider discovery: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("provider discovery status = %d, want 200: %s", resp.StatusCode, body)
	}

	var disc spec.Discovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		t.Fatalf("decode provider discovery: %v", err)
	}

	if !disc.RequiresHTTPSig() {
		t.Fatal("IETF provider discovery should require HTTP signatures")
	}

	if disc.TokenEndPoint == "" {
		t.Fatal("IETF provider discovery should advertise tokenEndPoint")
	}
}

func postTokenExchange(t *testing.T, providerBaseURL, clientHost, code string, sign func(*http.Request, []byte) error) int {
	t.Helper()

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientHost)
	form.Set("code", code)
	body := []byte(form.Encode())

	req, err := http.NewRequest(http.MethodPost, providerBaseURL+"/ocm/token", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create token request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if sign != nil {
		if err := sign(req, body); err != nil {
			t.Fatalf("sign token request: %v", err)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token exchange request failed: %v", err)
	}
	defer resp.Body.Close()

	return resp.StatusCode
}

func hostFromBaseURL(t *testing.T, baseURL string) string {
	t.Helper()

	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse base URL %q: %v", baseURL, err)
	}

	if u.Host == "" {
		t.Fatalf("base URL %q has empty host", baseURL)
	}

	return u.Host
}
