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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	tsinvite "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/invite"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func fetchDiscovery(t *testing.T, srv *harness.SubprocessServer) spec.Discovery {
	t.Helper()

	resp, err := srv.Client().Get(srv.BaseURL + "/.well-known/ocm")
	if err != nil {
		srv.DumpLogs(t)
		t.Fatalf("%s discovery GET: %v", srv.Name, err)
	}
	//nolint:errcheck // test cleanup: response body close
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		srv.DumpLogs(t)
		t.Fatalf("%s discovery status = %d, want 200", srv.Name, resp.StatusCode)
	}

	var disc spec.Discovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		t.Fatalf("%s decode discovery: %v", srv.Name, err)
	}

	return disc
}

func assertStrictLiveDiscovery(t *testing.T, serverName string, disc spec.Discovery, baseURL string) {
	t.Helper()

	if disc.APIVersion != "1.4.0" {
		t.Fatalf("%s apiVersion = %q, want 1.4.0", serverName, disc.APIVersion)
	}

	if !disc.Enabled {
		t.Fatalf("%s discovery disabled", serverName)
	}

	if disc.EndPoint == "" || disc.TokenEndPoint == "" {
		t.Fatalf("%s discovery missing endPoint or tokenEndPoint", serverName)
	}

	assertAbsoluteSameAuthority(t, serverName, disc.EndPoint, disc.TokenEndPoint)
	assertDiscoveryEndpointsMatchServerAuthority(t, serverName, disc, baseURL)

	if !disc.HasCapability("http-sig") {
		t.Fatalf("%s capabilities missing http-sig: %v", serverName, disc.Capabilities)
	}

	if !disc.HasCapability("exchange-token") {
		t.Fatalf("%s capabilities missing exchange-token: %v", serverName, disc.Capabilities)
	}

	if !disc.HasCriteria(spec.CriteriaMustUseHTTPSig) {
		t.Fatalf("%s criteria missing %s: %v", serverName, spec.CriteriaMustUseHTTPSig, disc.Criteria)
	}

	if !disc.HasCriteria(spec.CriteriaMustExchangeToken) {
		t.Fatalf("%s criteria missing %s: %v", serverName, spec.CriteriaMustExchangeToken, disc.Criteria)
	}

	fileRT, ok := findResourceType(disc, "file")
	if !ok {
		t.Fatalf("%s discovery missing file resource type", serverName)
	}

	if len(fileRT.ShareTypes) != 1 || fileRT.ShareTypes[0] != "user" {
		t.Fatalf("%s file shareTypes = %v, want [user]", serverName, fileRT.ShareTypes)
	}

	webdavRole, ok := fileRT.Protocols.StringRole("webdav")
	if !ok || webdavRole == "" {
		t.Fatalf("%s file protocols missing webdav sending role", serverName)
	}

	wr, ok := fileRT.Protocols.WebDAVReceive()
	if !ok {
		t.Fatalf("%s file protocols missing webdav-receive role", serverName)
	}

	if wr.URI != spec.WebDAVReceiveURIRelative {
		t.Fatalf("%s webdav-receive uri = %q, want relative", serverName, wr.URI)
	}
}

func assertDiscoveryEndpointsMatchServerAuthority(t *testing.T, serverName string, disc spec.Discovery, baseURL string) {
	t.Helper()

	base, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("%s parse base URL %q: %v", serverName, baseURL, err)
	}

	if base.Scheme == "" || base.Host == "" {
		t.Fatalf("%s base URL %q missing scheme or host", serverName, baseURL)
	}

	for _, endpoint := range []struct {
		name string
		raw  string
	}{
		{name: "endPoint", raw: disc.EndPoint},
		{name: "tokenEndPoint", raw: disc.TokenEndPoint},
	} {
		parsed, err := url.Parse(endpoint.raw)
		if err != nil {
			t.Fatalf("%s parse %s %q: %v", serverName, endpoint.name, endpoint.raw, err)
		}

		if parsed.Scheme != base.Scheme {
			t.Fatalf("%s %s scheme = %q, want %q from server authority", serverName, endpoint.name, parsed.Scheme, base.Scheme)
		}

		if !strings.EqualFold(parsed.Host, base.Host) {
			t.Fatalf("%s %s host = %q, want %q from server authority", serverName, endpoint.name, parsed.Host, base.Host)
		}
	}
}

func assertAbsoluteSameAuthority(t *testing.T, serverName, endPoint, tokenEndPoint string) {
	t.Helper()

	ep, err := url.Parse(endPoint)
	if err != nil {
		t.Fatalf("%s parse endPoint %q: %v", serverName, endPoint, err)
	}

	tp, err := url.Parse(tokenEndPoint)
	if err != nil {
		t.Fatalf("%s parse tokenEndPoint %q: %v", serverName, tokenEndPoint, err)
	}

	if !ep.IsAbs() || !tp.IsAbs() {
		t.Fatalf("%s endPoint/tokenEndPoint must be absolute: %q %q", serverName, endPoint, tokenEndPoint)
	}

	if ep.Scheme != tp.Scheme || !strings.EqualFold(ep.Host, tp.Host) {
		t.Fatalf("%s endPoint and tokenEndPoint differ in authority: %q vs %q", serverName, endPoint, tokenEndPoint)
	}
}

func findResourceType(disc spec.Discovery, name string) (spec.ResourceType, bool) {
	for _, rt := range disc.ResourceTypes {
		if rt.Name == name {
			return rt, true
		}
	}

	return spec.ResourceType{}, false
}

func subprocessSigner(t *testing.T, srv *harness.SubprocessServer) *crypto.RFC9421Signer {
	t.Helper()

	keyPath := filepath.Join(srv.TempDir, ".ocm", "keys", "signing.pem")

	km := crypto.NewKeyManager(keyPath, srv.BaseURL)
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("%s load signing key from %s: %v", srv.Name, keyPath, err)
	}

	return crypto.NewRFC9421Signer(km)
}

func postSignedJSONWithClient(
	t *testing.T,
	client *http.Client,
	targetURL string,
	body []byte,
	signer *crypto.RFC9421Signer,
) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build signed POST: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
		t.Fatalf("sign POST: %v", err)
	}

	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("signed POST %s: %v", targetURL, err)
	}

	return resp
}

func buildSignedInboundShareBody(
	shareWith, providerID, senderHost, webdavURI, sharedSecret string,
) []byte {
	return buildSignedInboundShareBodyWithSender(shareWith, providerID, "step14-sender", senderHost, webdavURI, sharedSecret)
}

// buildSignedInboundShareBodyWithSender is buildSignedInboundShareBody with an
// explicit sender user ID, used when the sender identity must match an
// exchanged invite.
func buildSignedInboundShareBodyWithSender(
	shareWith, providerID, senderUserID, senderHost, webdavURI, sharedSecret string,
) []byte {
	owner := address.FormatOutgoingOCMAddressFromUserID("step14-owner", senderHost)
	sender := address.FormatOutgoingOCMAddressFromUserID(senderUserID, senderHost)
	payload := spec.NewShareRequest{
		ShareWith:    shareWith,
		Name:         "step14-webdav-inbound.txt",
		ProviderID:   providerID,
		Owner:        owner,
		Sender:       sender,
		ShareType:    "user",
		ResourceType: "file",
		Protocol: spec.Protocol{
			Name: "webdav",
			WebDAV: &spec.WebDAVProtocol{
				URI:          webdavURI,
				SharedSecret: sharedSecret,
				Permissions:  []string{"read"},
				Requirements: []string{spec.RequirementMustExchangeToken},
			},
		},
	}

	body, err := json.Marshal(payload) //nolint:errchkjson // MarshalJSON emits fixed JSON; error is always nil in practice
	if err != nil {
		panic(err)
	}

	return body
}

func waitForInboxShareByProvider(
	t *testing.T,
	srv *harness.SubprocessServer,
	token, providerID string,
) string {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		shares := listInboxShares(t, srv, token)
		for _, share := range shares {
			if share["providerId"] == providerID {
				shareID, ok := share["shareId"].(string)
				if ok && shareID != "" {
					return shareID
				}
			}
		}

		time.Sleep(200 * time.Millisecond)
	}

	srv.DumpLogs(t)
	t.Fatalf("timed out waiting for inbox share providerID=%s on %s", providerID, srv.Name)

	return ""
}

func listInboxShares(t *testing.T, srv *harness.SubprocessServer, token string) []map[string]any {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, srv.BaseURL+"/api/inbox/shares", nil)
	if err != nil {
		t.Fatalf("build inbox list request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("inbox list GET: %v", err)
	}
	//nolint:errcheck // test cleanup: response body close
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

		t.Fatalf("inbox list status = %d: %s", resp.StatusCode, body)
	}

	var parsed struct {
		Shares []map[string]any `json:"shares"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode inbox list: %v", err)
	}

	return parsed.Shares
}

func getInboxShareDetail(t *testing.T, srv *harness.SubprocessServer, token, shareID string) map[string]any {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, srv.BaseURL+"/api/inbox/shares/"+shareID, nil)
	if err != nil {
		t.Fatalf("build inbox detail request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("inbox detail GET: %v", err)
	}
	//nolint:errcheck // test cleanup: response body close
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

		t.Fatalf("inbox detail status = %d: %s", resp.StatusCode, body)
	}

	var detail map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode inbox detail: %v", err)
	}

	return detail
}

func readOutgoingSharedSecret(t *testing.T, srv *harness.SubprocessServer, providerID string) string {
	t.Helper()

	path := filepath.Join(srv.TempDir, "data", "outgoing_shares.json")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var byProvider map[string]struct {
		SharedSecret string `json:"sharedSecret"`
	}
	if err := json.Unmarshal(raw, &byProvider); err != nil {
		t.Fatalf("decode outgoing shares: %v", err)
	}

	share, ok := byProvider[providerID]
	if !ok {
		t.Fatalf("outgoing share %q not found in persistence", providerID)
	}

	return share.SharedSecret
}

// exchangeInvitesBetweenPair runs a full invite exchange between the two
// strict pair servers: the provider admin creates an outgoing invite and the
// consumer admin imports and accepts it. Afterwards the consumer holds an
// accepted incoming invite from the provider admin and the provider holds an
// accepted outgoing invite for the consumer admin, so the bidirectional
// must-invite gate admits shares in both directions.
func exchangeInvitesBetweenPair(
	t *testing.T,
	provider, consumer *harness.SubprocessServer,
	providerToken, consumerToken string,
) {
	t.Helper()

	created, _, err := tsinvite.CreateOutgoing(provider.Client(), provider.BaseURL, providerToken)
	if err != nil {
		provider.DumpLogs(t)
		t.Fatalf("provider create outgoing invite: %v", err)
	}

	imported, _, err := tsinvite.Import(consumer.Client(), consumer.BaseURL, consumerToken, created.InviteString)
	if err != nil {
		consumer.DumpLogs(t)
		t.Fatalf("consumer import invite: %v", err)
	}

	if _, _, err := tsinvite.Accept(consumer.Client(), consumer.BaseURL, consumerToken, imported.ID); err != nil {
		provider.DumpLogs(t)
		consumer.DumpLogs(t)
		t.Fatalf("consumer accept invite: %v", err)
	}

	waitForOutgoingInviteAccepted(t, provider, created.Token)
}

func waitForOutgoingInviteAccepted(t *testing.T, srv *harness.SubprocessServer, token string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		status, _, err := tsinvite.OutgoingStatus(srv.TempDir, token)
		if err == nil && status == invites.InviteStatusAccepted {
			return
		}

		time.Sleep(100 * time.Millisecond)
	}

	srv.DumpLogs(t)
	t.Fatalf("timed out waiting for outgoing invite to reach accepted on %s", srv.Name)
}

// fetchCurrentUserID returns the authenticated user's canonical ID via
// GET /api/auth/me.
func fetchCurrentUserID(t *testing.T, srv *harness.SubprocessServer, token string) string {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, srv.BaseURL+"/api/auth/me", nil)
	if err != nil {
		t.Fatalf("build current-user request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("current-user GET: %v", err)
	}
	//nolint:errcheck // test cleanup: response body close
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

		t.Fatalf("current-user status = %d: %s", resp.StatusCode, body)
	}

	var parsed struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode current-user response: %v", err)
	}

	if parsed.ID == "" {
		t.Fatal("current-user response missing id")
	}

	return parsed.ID
}

func loginSubprocessAdminWithClient(t *testing.T, srv *harness.SubprocessServer) string {
	t.Helper()

	passwords := []string{"testpassword123", "admin"}
	for _, password := range passwords {
		if token, _, ok := tryLoginWithClient(t, srv.Client(), srv.BaseURL, "admin", password); ok {
			return token
		}
	}

	logs := srv.ReadLog(t)

	password := extractBootstrapPassword(logs)
	if password == "" {
		t.Fatalf("bootstrap admin password not found in server log:\n%s", logs)
	}

	token, body, ok := tryLoginWithClient(t, srv.Client(), srv.BaseURL, "admin", password)
	if !ok {
		t.Fatalf("login failed with bootstrap password: %s", body)
	}

	return token
}

func tryLoginWithClient(t *testing.T, client *http.Client, baseURL, username, password string) (string, string, bool) {
	t.Helper()

	reqBody, err := json.Marshal(map[string]string{ //nolint:errchkjson // MarshalJSON emits fixed JSON; error is always nil in practice
		"username": username,
		"password": password,
	})
	if err != nil {
		t.Fatalf("encode login request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/auth/login", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("build login request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("login POST: %v", err)
	}
	//nolint:errcheck // test cleanup: response body close
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", string(body), false
	}

	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decode login response: %v", err)
	}

	if parsed.Token == "" {
		return "", string(body), false
	}

	return parsed.Token, string(body), true
}

func createOutgoingShareWithClient(
	t *testing.T,
	srv *harness.SubprocessServer,
	token string,
	payload map[string]any,
) (int, string) {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal outgoing share payload: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, srv.BaseURL+"/api/shares/outgoing", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build outgoing share request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("outgoing share POST: %v", err)
	}
	//nolint:errcheck // test cleanup: response body close
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	return resp.StatusCode, string(respBody)
}

func exchangeSignedAuthorizationCode(
	t *testing.T,
	client *http.Client,
	tokenEndpoint, clientID, code string,
	signer *crypto.RFC9421Signer,
) spec.TokenResponse {
	t.Helper()

	form := url.Values{}
	form.Set("grant_type", spec.GrantTypeAuthorizationCode)
	form.Set("client_id", clientID)
	form.Set("code", code)
	body := []byte(form.Encode())

	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := signer.SignRequest(req, body); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
		t.Fatalf("sign token request: %v", err)
	}

	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("token exchange POST: %v", err)
	}
	//nolint:errcheck // test cleanup: response body close
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

		t.Fatalf("token exchange status = %d: %s", resp.StatusCode, respBody)
	}

	var tokenResp spec.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	return tokenResp
}
