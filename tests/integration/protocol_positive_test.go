// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	tsprotocol "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/protocol"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestProtocolPositiveStrictTwoServer covers strict two-subprocess discovery,
// signed multi outgoing emission, signed named-webdav inbound admission,
// same-authority token exchange, Bearer WebDAV content, and duplicate inbound
// idempotency.
func TestProtocolPositiveStrictTwoServer(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	pair := startStrictProtocolPair(t)
	defer pair.Stop(t)

	provider := pair.Server1
	consumer := pair.Server2

	providerDisc := fetchDiscovery(t, provider)
	consumerDisc := fetchDiscovery(t, consumer)
	assertStrictLiveDiscovery(t, provider.Name, providerDisc, provider.BaseURL)
	assertStrictLiveDiscovery(t, consumer.Name, consumerDisc, consumer.BaseURL)

	testContent := []byte("strict positive protocol proof file content")

	testFile := writeShareFileInContentRoot(t, provider.TempDir, "protocol-positive.txt", testContent)

	providerToken := loginSubprocessAdminWithClient(t, provider)
	consumerToken := loginSubprocessAdminWithClient(t, consumer)

	consumerHost := hostFromBaseURL(t, consumer.BaseURL)
	providerHost := hostFromBaseURL(t, provider.BaseURL)

	// Strict mode enforces must-invite: exchange an invite before any share.
	exchangeInvitesBetweenPair(t, provider, consumer, providerToken, consumerToken)

	providerID, webdavID := createAndVerifyMultiShare(t, provider, consumer, providerToken, consumerToken, consumerHost, testFile)
	webdavBody, webdavSecret, consumerSigner := postWebDAVInboundShare(t, provider, consumer, providerToken, consumerToken, providerHost, consumerHost)

	tokenResp, sharedSecret := exchangeProviderToken(t, provider, consumer, providerDisc.TokenEndPoint, consumerHost, providerID)

	webdavURL := provider.BaseURL + "/webdav/ocm/" + webdavID + "/" + url.PathEscape(filepath.Base(testFile))
	assertBearerWebDAVContent(t, provider, webdavURL, tokenResp.AccessToken, testContent)
	assertSharedSecretWebDAVRejected(t, provider, webdavURL, sharedSecret)
	assertDuplicateInboundIdempotent(t, provider, consumer, webdavBody, consumerSigner)

	secrets := []string{sharedSecret, webdavSecret, tokenResp.AccessToken}
	assertNoSecretInLogs(t, secrets, provider, consumer)
}

// createAndVerifyMultiShare creates the outgoing multi share to the consumer
// and verifies inbox projection, returning providerId and webdavId.
func createAndVerifyMultiShare(t *testing.T, provider, consumer *harness.SubprocessServer, providerToken, consumerToken, consumerHost, testFile string) (string, string) {
	t.Helper()

	status, body := createOutgoingShareWithClient(t, provider, providerToken, map[string]any{
		"receiverDomain": consumerHost,
		"shareWith":      "admin@" + consumerHost,
		"localPath":      testFile,
		"permissions":    []string{"read"},
	})
	if status != http.StatusCreated {
		provider.DumpLogs(t)
		consumer.DumpLogs(t)
		t.Fatalf("outgoing multi share: expected 201, got %d: %s", status, body)
	}

	var outgoingCreated struct {
		ProviderID string `json:"providerId"`
		WebDAVID   string `json:"webdavId"`
		Status     string `json:"status"`
	}
	if err := json.Unmarshal([]byte(body), &outgoingCreated); err != nil {
		t.Fatalf("decode outgoing share response: %v", err)
	}

	if outgoingCreated.ProviderID == "" || outgoingCreated.WebDAVID == "" {
		t.Fatalf("outgoing share missing providerId/webdavId: %s", body)
	}

	if outgoingCreated.Status != "sent" {
		t.Fatalf("outgoing share status = %q, want sent", outgoingCreated.Status)
	}

	multiShareID := waitForInboxShareByProvider(t, consumer, consumerToken, outgoingCreated.ProviderID)

	multiDetail := getInboxShareDetail(t, consumer, consumerToken, multiShareID)
	if multiDetail["providerId"] != outgoingCreated.ProviderID {
		t.Fatalf("inbox detail providerId = %v, want %s", multiDetail["providerId"], outgoingCreated.ProviderID)
	}

	proto, ok := multiDetail["protocol"].(map[string]any)
	if !ok {
		t.Fatalf("inbox detail protocol missing: %v", multiDetail)
	}

	if proto["name"] != "multi" {
		t.Fatalf("inbox detail protocol.name = %v, want multi", proto["name"])
	}

	return outgoingCreated.ProviderID, outgoingCreated.WebDAVID
}

// postWebDAVInboundShare posts the signed named-webdav inbound share and
// verifies inbox projection, returning the body, secret, and signer for the
// duplicate-post idempotency check.
func postWebDAVInboundShare(t *testing.T, provider, consumer *harness.SubprocessServer, providerToken, consumerToken, providerHost, consumerHost string) ([]byte, string, *crypto.RFC9421Signer) {
	t.Helper()

	webdavProviderID := "webdav-inbound-positive"
	webdavSecret := "webdav-shared-secret"
	// The inbound sender must match the exchanged invite: the consumer admin's
	// canonical federated identity, not an arbitrary user.
	consumerAdminID := fetchCurrentUserID(t, consumer, consumerToken)
	webdavBody := buildSignedInboundShareBodyWithSender(t, "admin@"+providerHost, webdavProviderID, consumerAdminID, consumerHost, "webdav-uri",
		webdavSecret,
	)
	consumerSigner := subprocessSigner(t, consumer)

	webdavResp := postSignedJSONWithClient(t, consumer.Client(), provider.BaseURL+"/ocm/shares", webdavBody, consumerSigner) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	defer tshttp.MustClose(t, webdavResp.Body)

	if webdavResp.StatusCode != http.StatusCreated {
		respBody, err := io.ReadAll(webdavResp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

		provider.DumpLogs(t)
		consumer.DumpLogs(t)
		t.Fatalf("signed webdav inbound share: expected 201, got %d: %s", webdavResp.StatusCode, respBody)
	}

	webdavShareID := waitForInboxShareByProvider(t, provider, providerToken, webdavProviderID)

	webdavDetail := getInboxShareDetail(t, provider, providerToken, webdavShareID)
	if webdavDetail["providerId"] != webdavProviderID {
		t.Fatalf("webdav inbox providerId = %v, want %s", webdavDetail["providerId"], webdavProviderID)
	}

	return webdavBody, webdavSecret, consumerSigner
}

// exchangeProviderToken reads the outgoing shared secret and runs the signed
// authorization code exchange, returning the token response and shared secret.
func exchangeProviderToken(t *testing.T, provider, consumer *harness.SubprocessServer, tokenEndpoint, consumerHost, providerID string) (spec.TokenResponse, string) {
	t.Helper()

	sharedSecret := readOutgoingSharedSecret(t, provider, providerID)
	if sharedSecret == "" {
		t.Fatal("outgoing persistence missing shared secret for token exchange")
	}

	tokenResp := exchangeSignedAuthorizationCode(
		t,
		consumer.Client(),
		tokenEndpoint,
		consumerHost,
		sharedSecret,
		subprocessSigner(t, consumer),
	)
	if tokenResp.TokenType != "Bearer" {
		t.Fatalf("token_type = %q, want Bearer", tokenResp.TokenType)
	}

	if tokenResp.AccessToken == "" {
		t.Fatal("token exchange returned empty access_token")
	}

	return tokenResp, sharedSecret
}

// assertBearerWebDAVContent checks bearer access to the shared file content.
func assertBearerWebDAVContent(t *testing.T, provider *harness.SubprocessServer, webdavURL, accessToken string, testContent []byte) {
	t.Helper()

	bearerReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, webdavURL, nil)
	if err != nil {
		t.Fatalf("create bearer webdav request: %v", err)
	}

	bearerReq.Header.Set("Authorization", "Bearer "+accessToken)

	bearerResp, err := provider.Client().Do(bearerReq) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("bearer webdav GET: %v", err)
	}
	defer tshttp.MustClose(t, bearerResp.Body)

	if bearerResp.StatusCode != http.StatusOK {
		respBody, rerr := io.ReadAll(bearerResp.Body)
		if rerr != nil {
			t.Fatalf("read response body: %v", rerr)
		}

		t.Fatalf("bearer webdav: expected 200, got %d: %s", bearerResp.StatusCode, respBody)
	}

	gotContent, err := io.ReadAll(bearerResp.Body)
	if err != nil {
		t.Fatalf("read bearer webdav body: %v", err)
	}

	if !bytes.Equal(gotContent, testContent) {
		t.Fatalf("bearer webdav body = %q, want %q", gotContent, testContent)
	}
}

// assertSharedSecretWebDAVRejected checks the raw shared secret is not a
// valid bearer credential.
func assertSharedSecretWebDAVRejected(t *testing.T, provider *harness.SubprocessServer, webdavURL, sharedSecret string) {
	t.Helper()

	secretReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, webdavURL, nil)
	if err != nil {
		t.Fatalf("create shared-secret webdav request: %v", err)
	}

	secretReq.Header.Set("Authorization", "Bearer "+sharedSecret)

	secretResp, err := provider.Client().Do(secretReq) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("shared-secret webdav GET: %v", err)
	}
	defer tshttp.MustClose(t, secretResp.Body)

	if secretResp.StatusCode != http.StatusUnauthorized {
		respBody, err := io.ReadAll(secretResp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

		t.Fatalf("shared-secret webdav: expected 401, got %d: %s", secretResp.StatusCode, respBody)
	}
}

// assertDuplicateInboundIdempotent reposts the inbound share and checks the
// duplicate is accepted without changing persistence.
func assertDuplicateInboundIdempotent(t *testing.T, provider, consumer *harness.SubprocessServer, webdavBody []byte, consumerSigner *crypto.RFC9421Signer) {
	t.Helper()

	beforeSnap, err := tsprotocol.SnapshotPersistence(provider.TempDir)
	if err != nil {
		t.Fatalf("snapshot persistence before duplicate: %v", err)
	}

	dupResp := postSignedJSONWithClient(t, consumer.Client(), provider.BaseURL+"/ocm/shares", webdavBody, consumerSigner) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	defer tshttp.MustClose(t, dupResp.Body)

	if dupResp.StatusCode != http.StatusCreated {
		respBody, rerr := io.ReadAll(dupResp.Body)
		if rerr != nil {
			t.Fatalf("read response body: %v", rerr)
		}

		t.Fatalf("duplicate webdav inbound share: expected 201, got %d: %s", dupResp.StatusCode, respBody)
	}

	afterSnap, err := tsprotocol.SnapshotPersistence(provider.TempDir)
	if err != nil {
		t.Fatalf("snapshot persistence after duplicate: %v", err)
	}

	assertPersistenceUnchanged(t, beforeSnap, afterSnap)
}
