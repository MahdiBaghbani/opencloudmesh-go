// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestTokenExchangeFlow exercises the full signed code-flow happy path:
// share creation to a strict peer, signed token exchange, and WebDAV access
// with the exchanged bearer token.
func TestTokenExchangeFlow(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
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

	testContent := []byte("Hello from token exchange test - this is the file content!")
	testFile := writeShareFileInContentRoot(t, sender.TempDir, "test.txt", testContent)

	receiver := startStrictCodeFlowReceiver(t)
	defer receiver.Close()

	_, webdavID, sharedSecret := createTokenFlowShare(t, sender, receiver, testFile)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", receiver.peerDomain)
	form.Set("code", sharedSecret)

	assertUnsignedTokenRejected(t, sender, form)
	accessToken := exchangeSignedTokenFlowCode(t, sender, receiver, form)
	assertWebDAVBearerContent(t, sender.BaseURL, webdavID, testFile, accessToken, testContent)
}

// createTokenFlowShare creates the outgoing share to the strict receiver and
// verifies the captured inbound request, returning the share identifiers and
// shared secret.
func createTokenFlowShare(t *testing.T, sender *harness.SubprocessServer, receiver *strictCodeFlowReceiver, testFile string) (string, string, string) {
	t.Helper()

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
		t.Fatalf("captured providerID %q does not match API response %q", captured.ProviderID, created.ProviderID)
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

	return created.ProviderID, created.WebDAVID, captured.SharedSecret
}

// assertUnsignedTokenRejected checks an unsigned token request is rejected with 401.
func assertUnsignedTokenRejected(t *testing.T, sender *harness.SubprocessServer, form url.Values) {
	t.Helper()

	unsignedReq, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		sender.BaseURL+"/ocm/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("failed to build unsigned token request: %v", err)
	}

	unsignedReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	unsignedResp, err := http.DefaultClient.Do(unsignedReq) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("failed to call unsigned token endpoint: %v", err)
	}
	defer tshttp.MustClose(t, unsignedResp.Body)

	if unsignedResp.StatusCode != http.StatusUnauthorized {
		respBody, err := io.ReadAll(unsignedResp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

		t.Fatalf("expected unsigned token request to be rejected with 401, got %d: %s", unsignedResp.StatusCode, respBody)
	}
}

// exchangeSignedTokenFlowCode posts the signed token request and returns the
// exchanged access token.
func exchangeSignedTokenFlowCode(t *testing.T, sender *harness.SubprocessServer, receiver *strictCodeFlowReceiver, form url.Values) string {
	t.Helper()

	signedReq, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		sender.BaseURL+"/ocm/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("failed to create signed token request: %v", err)
	}

	signedReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if serr := receiver.signer.Sign(signedReq); serr != nil {
		t.Fatalf("failed to sign token request: %v", serr)
	}

	signedResp, err := http.DefaultClient.Do(signedReq) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("failed to call signed token endpoint: %v", err)
	}
	defer tshttp.MustClose(t, signedResp.Body)

	if signedResp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(signedResp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

		t.Fatalf("expected signed token request to succeed, got %d: %s", signedResp.StatusCode, respBody)
	}

	var tokenResp spec.TokenResponse
	if err := json.NewDecoder(signedResp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	if tokenResp.AccessToken == "" {
		t.Fatal("signed token exchange returned empty access_token")
	}

	return tokenResp.AccessToken
}

// assertWebDAVBearerContent checks bearer access to the shared file over WebDAV.
func assertWebDAVBearerContent(t *testing.T, senderBaseURL, webdavID, testFile, accessToken string, wantContent []byte) {
	t.Helper()

	webdavURL := senderBaseURL + "/webdav/ocm/" + webdavID + "/" + url.PathEscape(filepath.Base(testFile))

	webdavReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, webdavURL, nil)
	if err != nil {
		t.Fatalf("failed to create WebDAV request: %v", err)
	}

	webdavReq.Header.Set("Authorization", "Bearer "+accessToken)

	webdavResp, err := http.DefaultClient.Do(webdavReq) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("failed to call WebDAV endpoint: %v", err)
	}
	defer tshttp.MustClose(t, webdavResp.Body)

	if webdavResp.StatusCode != http.StatusOK {
		respBody, rerr := io.ReadAll(webdavResp.Body)
		if rerr != nil {
			t.Fatalf("read response body: %v", rerr)
		}

		t.Fatalf("expected WebDAV bearer access to succeed, got %d: %s", webdavResp.StatusCode, respBody)
	}

	gotContent, err := io.ReadAll(webdavResp.Body)
	if err != nil {
		t.Fatalf("failed to read WebDAV response body: %v", err)
	}

	if !bytes.Equal(gotContent, wantContent) {
		t.Fatalf("unexpected WebDAV body %q, want %q", gotContent, wantContent)
	}
}

func TestIETFHarness_WiresCryptoDeps(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

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

	signedReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, provider.BaseURL+"/ocm/token", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create signed token request: %v", err)
	}

	signedReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if serr := client.Deps.Signer.SignRequest(signedReq, body); serr != nil {
		t.Fatalf("sign token request: %v", serr)
	}

	sigInput := signedReq.Header.Get("Signature-Input")
	if !strings.HasPrefix(sigInput, "ocm=") {
		t.Fatalf("Signature-Input = %q, want ocm= prefix", sigInput)
	}

	if signedReq.Header.Get("Signature") == "" {
		t.Fatal("expected Signature header on signed token request")
	}

	signedResp, err := http.DefaultClient.Do(signedReq) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("signed token exchange request failed: %v", err)
	}
	defer tshttp.MustClose(t, signedResp.Body)

	if signedResp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(signedResp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

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

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, client.BaseURL+"/ocm/jwks", nil)
	if err != nil {
		t.Fatalf("build client JWKS request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("fetch client JWKS: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

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

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, provider.BaseURL+"/.well-known/ocm", nil)
	if err != nil {
		t.Fatalf("build provider discovery request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("fetch provider discovery: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

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

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, providerBaseURL+"/ocm/token", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create token request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if sign != nil {
		if serr := sign(req, body); serr != nil {
			t.Fatalf("sign token request: %v", serr)
		}
	}

	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("token exchange request failed: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

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
