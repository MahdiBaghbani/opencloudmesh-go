// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	tsprotocol "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/protocol"
)

// TestProtocolPositiveStrictTwoServer covers strict two-subprocess discovery,
// signed multi outgoing emission, signed named-webdav inbound admission,
// same-authority token exchange, Bearer WebDAV content, and duplicate inbound
// idempotency.
func TestProtocolPositiveStrictTwoServer(t *testing.T) { //nolint:cyclop,maintidx // integration e2e test: end-to-end flow complexity is inherent to the protocol narrative
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

	testFile := filepath.Join(t.TempDir(), "protocol-positive.txt")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	providerToken := loginSubprocessAdminWithClient(t, provider)
	consumerToken := loginSubprocessAdminWithClient(t, consumer)

	consumerHost := hostFromBaseURL(t, consumer.BaseURL)
	providerHost := hostFromBaseURL(t, provider.BaseURL)

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

	webdavProviderID := "webdav-inbound-positive"
	webdavSecret := "webdav-shared-secret"
	webdavBody := buildSignedInboundShareBody("admin@"+providerHost, webdavProviderID, consumerHost, "webdav-uri",
		webdavSecret,
	)
	consumerSigner := subprocessSigner(t, consumer)

	webdavResp := postSignedJSONWithClient(t, consumer.Client(), provider.BaseURL+"/ocm/shares", webdavBody, consumerSigner)
	//nolint:errcheck // test cleanup: response body close
	defer webdavResp.Body.Close()

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

	sharedSecret := readOutgoingSharedSecret(t, provider, outgoingCreated.ProviderID)
	if sharedSecret == "" {
		t.Fatal("outgoing persistence missing shared secret for token exchange")
	}

	tokenResp := exchangeSignedAuthorizationCode(
		t,
		consumer.Client(),
		providerDisc.TokenEndPoint,
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

	fileName := filepath.Base(testFile)
	webdavURL := provider.BaseURL + "/webdav/ocm/" + outgoingCreated.WebDAVID + "/" + url.PathEscape(fileName)

	bearerReq, err := http.NewRequest(http.MethodGet, webdavURL, nil)
	if err != nil {
		t.Fatalf("create bearer webdav request: %v", err)
	}

	bearerReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	bearerResp, err := provider.Client().Do(bearerReq)
	if err != nil {
		t.Fatalf("bearer webdav GET: %v", err)
	}
	//nolint:errcheck // test cleanup: response body close
	defer bearerResp.Body.Close()

	if bearerResp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(bearerResp.Body) //nolint:govet // shadow: sequential err in table-driven test is benign
		if err != nil {
			t.Fatalf("read response body: %v", err)
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

	secretReq, err := http.NewRequest(http.MethodGet, webdavURL, nil)
	if err != nil {
		t.Fatalf("create shared-secret webdav request: %v", err)
	}

	secretReq.Header.Set("Authorization", "Bearer "+sharedSecret)

	secretResp, err := provider.Client().Do(secretReq)
	if err != nil {
		t.Fatalf("shared-secret webdav GET: %v", err)
	}
	//nolint:errcheck // test cleanup: response body close
	defer secretResp.Body.Close()

	if secretResp.StatusCode != http.StatusUnauthorized {
		respBody, err := io.ReadAll(secretResp.Body) //nolint:govet // shadow: sequential err in table-driven test is benign
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

		t.Fatalf("shared-secret webdav: expected 401, got %d: %s", secretResp.StatusCode, respBody)
	}

	beforeSnap, err := tsprotocol.SnapshotPersistence(provider.TempDir)
	if err != nil {
		t.Fatalf("snapshot persistence before duplicate: %v", err)
	}

	dupResp := postSignedJSONWithClient(t, consumer.Client(), provider.BaseURL+"/ocm/shares", webdavBody, consumerSigner)
	//nolint:errcheck // test cleanup: response body close
	defer dupResp.Body.Close()

	if dupResp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(dupResp.Body) //nolint:govet // shadow: sequential err in table-driven test is benign
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

		t.Fatalf("duplicate webdav inbound share: expected 200, got %d: %s", dupResp.StatusCode, respBody)
	}

	afterSnap, err := tsprotocol.SnapshotPersistence(provider.TempDir)
	if err != nil {
		t.Fatalf("snapshot persistence after duplicate: %v", err)
	}

	assertPersistenceUnchanged(t, beforeSnap, afterSnap)

	secrets := []string{sharedSecret, webdavSecret, tokenResp.AccessToken}
	assertNoSecretInLogs(t, secrets, provider, consumer)
}
