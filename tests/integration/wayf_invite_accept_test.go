// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	tsinvite "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/invite"
	tsession "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/session"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestWayfInviteAcceptTwoInstance proves the MVP WAYF/discover path without
// Playwright: Alice discovers Bob's inviteAcceptDialog, the redirect URL carries
// token and Alice providerDomain, Bob preserves accept-invite query through login
// redirect, Bob accepts via API, and Alice records accepted state.
func TestWayfInviteAcceptTwoInstance(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}

	alice, bob := startStrictInvitePair(t, true)
	defer alice.Stop(t)
	defer bob.Stop(t)

	aliceClient := alice.Client()
	bobClient := bob.Client()
	noRedirect := &http.Client{
		Timeout:   bobClient.Timeout,
		Transport: bobClient.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	created := createAliceOutgoingInvite(t, alice, aliceClient)
	disc := discoverBobInviteDialog(t, alice, bob, aliceClient)
	redirectURL, acceptPath := buildCheckedWAYFRedirect(t, disc, created)
	assertAcceptInviteRedirectsToLogin(t, noRedirect, bob, redirectURL, acceptPath)
	bobAcceptsAliceInvite(t, alice, bob, bobClient, created)
}

// createAliceOutgoingInvite logs in to alice and creates an outgoing invite.
func createAliceOutgoingInvite(t *testing.T, alice *harness.SubprocessServer, aliceClient *http.Client) *tsinvite.OutgoingCreateResponse {
	t.Helper()

	aliceToken, err := tsession.Login(t.Context(), aliceClient, alice.BaseURL, "admin", "")
	if err != nil {
		alice.DumpLogs(t)
		t.Fatalf("login alice: %v", err)
	}

	created, _, err := tsinvite.CreateOutgoing(t.Context(), aliceClient, alice.BaseURL, aliceToken)
	if err != nil {
		alice.DumpLogs(t)
		t.Fatalf("alice create outgoing invite: %v", err)
	}

	return created
}

// discoverBobInviteDialog discovers bob from alice and checks the invite
// accept dialog fields.
func discoverBobInviteDialog(t *testing.T, alice, bob *harness.SubprocessServer, aliceClient *http.Client) *tsinvite.DiscoverResponse {
	t.Helper()

	disc, status, err := tsinvite.DiscoverProvider(t.Context(), aliceClient, alice.BaseURL, bob.BaseURL)
	if err != nil {
		alice.DumpLogs(t)
		bob.DumpLogs(t)
		t.Fatalf("alice discover bob: %v", err)
	}

	if status != http.StatusOK {
		alice.DumpLogs(t)
		bob.DumpLogs(t)
		t.Fatalf("discover status = %d, want 200; body success=%v error=%q reason=%q",
			status, disc.Success, disc.Error, disc.ReasonCode)
	}

	if !disc.Success {
		t.Fatalf("discover success=false: %q (%s)", disc.Error, disc.ReasonCode)
	}

	if disc.InviteAcceptDialogAbsolute == "" {
		t.Fatal("discover missing inviteAcceptDialogAbsolute")
	}

	if disc.Discovery == nil || disc.Discovery.InviteAcceptDialog == "" {
		t.Fatal("discover missing peer inviteAcceptDialog")
	}

	if !strings.Contains(disc.InviteAcceptDialogAbsolute, bob.BaseURL) &&
		!strings.Contains(disc.InviteAcceptDialogAbsolute, "/ui/accept-invite") {
		t.Fatalf("inviteAcceptDialogAbsolute = %q, expected bob accept-invite URL", disc.InviteAcceptDialogAbsolute)
	}

	return disc
}

// buildCheckedWAYFRedirect builds the WAYF redirect URL and checks the token
// and providerDomain query parameters, returning the URL and its path+query.
func buildCheckedWAYFRedirect(t *testing.T, disc *tsinvite.DiscoverResponse, created *tsinvite.OutgoingCreateResponse) (string, string) {
	t.Helper()

	redirectURL := tsinvite.BuildWAYFRedirectURL(
		disc.InviteAcceptDialogAbsolute,
		created.Token,
		created.ProviderFQDN,
	)

	redirectParsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse redirect URL: %v", err)
	}

	if redirectParsed.Query().Get("token") != created.Token {
		t.Fatalf("redirect token = %q, want %q", redirectParsed.Query().Get("token"), created.Token)
	}

	if redirectParsed.Query().Get("providerDomain") != created.ProviderFQDN {
		t.Fatalf("redirect providerDomain = %q, want %q",
			redirectParsed.Query().Get("providerDomain"), created.ProviderFQDN)
	}

	acceptPath := redirectParsed.Path
	if redirectParsed.RawQuery != "" {
		acceptPath += "?" + redirectParsed.RawQuery
	}

	return redirectURL, acceptPath
}

// assertAcceptInviteRedirectsToLogin checks the unauthenticated accept-invite
// request redirects to login preserving the accept path.
func assertAcceptInviteRedirectsToLogin(t *testing.T, noRedirect *http.Client, bob *harness.SubprocessServer, redirectURL, acceptPath string) {
	t.Helper()

	acceptReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, redirectURL, nil)
	if err != nil {
		t.Fatalf("build bob accept-invite request: %v", err)
	}

	acceptResp, err := noRedirect.Do(acceptReq) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		bob.DumpLogs(t)
		t.Fatalf("GET bob accept-invite unauthenticated: %v", err)
	}
	defer tshttp.MustClose(t, acceptResp.Body)

	if _, derr := io.Copy(io.Discard, acceptResp.Body); derr != nil {
		t.Errorf("drain response body: %v", derr)
	}

	if acceptResp.StatusCode != http.StatusFound {
		bob.DumpLogs(t)
		t.Fatalf("accept-invite unauthenticated status = %d, want 302", acceptResp.StatusCode)
	}

	loginLocation := acceptResp.Header.Get("Location")
	if loginLocation == "" {
		t.Fatal("accept-invite redirect missing Location header")
	}

	loginURL, err := url.Parse(loginLocation)
	if err != nil {
		t.Fatalf("parse login Location: %v", err)
	}

	if !strings.HasSuffix(loginURL.Path, "/ui/login") {
		t.Fatalf("expected redirect to login, got path %q", loginURL.Path)
	}

	returnURL := loginURL.Query().Get("redirect")
	if returnURL != acceptPath {
		t.Fatalf("login redirect param = %q, want %q", returnURL, acceptPath)
	}
}

// bobAcceptsAliceInvite runs bob's login, import, accept flow and verifies
// both sides record the accepted state.
func bobAcceptsAliceInvite(t *testing.T, alice, bob *harness.SubprocessServer, bobClient *http.Client, created *tsinvite.OutgoingCreateResponse) {
	t.Helper()

	bobToken, err := tsession.Login(t.Context(), bobClient, bob.BaseURL, "admin", "")
	if err != nil {
		bob.DumpLogs(t)
		t.Fatalf("login bob: %v", err)
	}

	imported, _, err := tsinvite.Import(t.Context(), bobClient, bob.BaseURL, bobToken, created.InviteString)
	if err != nil {
		bob.DumpLogs(t)
		t.Fatalf("bob import invite: %v", err)
	}

	if _, _, aerr := tsinvite.Accept(t.Context(), bobClient, bob.BaseURL, bobToken, imported.ID); aerr != nil {
		alice.DumpLogs(t)
		bob.DumpLogs(t)
		t.Fatalf("bob accept invite via API: %v", aerr)
	}

	list, _, err := tsinvite.ListInbox(t.Context(), bobClient, bob.BaseURL, bobToken)
	if err != nil {
		bob.DumpLogs(t)
		t.Fatalf("bob list inbox invites: %v", err)
	}

	bobInvite, err := tsinvite.FindInboxInvite(list, imported.ID)
	if err != nil {
		t.Fatalf("bob inbox missing accepted invite: %v", err)
	}

	if bobInvite.Status != invites.InviteStatusAccepted {
		t.Fatalf("bob inbox status = %q, want accepted", bobInvite.Status)
	}

	aliceStatus, acceptedBy, err := tsinvite.OutgoingStatus(alice.TempDir, created.Token)
	if err != nil {
		alice.DumpLogs(t)
		t.Fatalf("read alice outgoing invite status: %v", err)
	}

	if aliceStatus != invites.InviteStatusAccepted {
		t.Fatalf("alice outgoing status = %q, want accepted", aliceStatus)
	}

	if acceptedBy == "" {
		t.Fatal("alice outgoing invite missing accepted_by recipient provider")
	}
}
