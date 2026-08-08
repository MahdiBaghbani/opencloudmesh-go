// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// disableMustInvite opts a test server out of must-invite enforcement. Tests
// that exercise inbound-share identity handling without seeding an invite use
// this to keep the legacy acceptance path.
func disableMustInvite(cfg *config.Config) {
	off := false
	cfg.OCM.Invite = &config.InviteConfig{EnforceMustInvite: &off}
}

func postSignedJSON(t *testing.T, targetURL string, body []byte, signer *crypto.RFC9421Signer) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to build signed request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if serr := signer.Sign(req); serr != nil {
		t.Fatalf("failed to sign request: %v", serr)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("signed POST failed: %v", err)
	}

	return resp
}

// TestInviteAccepted_UserID_IsRevaStyleFederatedOpaqueID verifies that the
// /ocm/invite-accepted endpoint returns userID as a Reva-style federated
// opaque ID (unpadded base64url encoding of userID@idp per RFC 4648
// Section 5), not the old format (base64std(userID)@provider).
func TestInviteAccepted_UserID_IsRevaStyleFederatedOpaqueID(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := harness.StartTestServer(t)
	defer ts.Stop(t)

	peer := startStrictCodeFlowReceiver(t)
	defer peer.Close()

	d := ts.Deps
	localProvider := d.LocalIdentity.ProviderDomain

	// Seed a local user (the invite creator whose identity appears in the response)
	localUser := &identity.User{
		ID:          "invite-test-user-uuid",
		Username:    "inviteuser",
		Email:       "inviteuser@localhost",
		DisplayName: "Invite Test User",
	}
	if err := d.PartyRepo.Create(context.Background(), localUser); err != nil {
		t.Fatalf("failed to seed local user: %v", err)
	}

	// Seed an outgoing invite
	invite := &invitesoutgoing.OutgoingInvite{
		Token:           "identity-test-token",
		ProviderFQDN:    localProvider,
		CreatedByUserID: localUser.ID,
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
	if err := d.OutgoingInviteRepo.Create(context.Background(), invite); err != nil {
		t.Fatalf("failed to seed outgoing invite: %v", err)
	}

	// POST /ocm/invite-accepted
	reqBody := spec.InviteAcceptedRequest{
		RecipientProvider: peer.peerDomain,
		Token:             "identity-test-token",
		UserID:            "remote-user@" + peer.peerDomain,
		Email:             "remote@example.com",
		Name:              "Remote User",
	}

	response := postInviteAccepted(t, ts.BaseURL, peer, reqBody)
	assertFederatedOpaqueUserID(t, response.UserID, localUser.ID, localProvider)
}

// postInviteAccepted posts the invite-accepted request and decodes the OK response.
func postInviteAccepted(t *testing.T, baseURL string, peer *strictCodeFlowReceiver, reqBody spec.InviteAcceptedRequest) spec.InviteAcceptedResponse {
	t.Helper()

	body := tshttp.MustMarshalJSON(t, reqBody)

	resp := postSignedJSON(t, baseURL+"/ocm/invite-accepted", body, peer.signer) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(respBody))
	}

	var response spec.InviteAcceptedResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	return response
}

// assertFederatedOpaqueUserID checks the response userID is the Reva-style
// federated opaque ID for the local user.
func assertFederatedOpaqueUserID(t *testing.T, responseUserID, localUserID, localProvider string) {
	t.Helper()

	// userID must match EncodeFederatedOpaqueID output
	expectedUserID := address.EncodeFederatedOpaqueID(localUserID, localProvider)
	if responseUserID != expectedUserID {
		t.Errorf("userID = %q, want %q", responseUserID, expectedUserID)
	}

	decodedUserID, decodedIDP := decodeFederatedOpaqueUserID(t, responseUserID)

	if decodedUserID != localUserID {
		t.Errorf("decoded userID = %q, want %q", decodedUserID, localUserID)
	}

	if decodedIDP != localProvider {
		t.Errorf("decoded idp = %q, want %q", decodedIDP, localProvider)
	}

	// userID must NOT be in the old format (base64std(uid)@provider)
	oldFormatSuffix := "@" + localProvider
	if strings.HasSuffix(responseUserID, oldFormatSuffix) {
		t.Errorf("userID %q appears to use old OCM address format (base64std(uid)@provider); "+
			"invite userID should be an opaque ID without @provider suffix", responseUserID)
	}

	// base64url uses '-' and '_' instead of '+' and '/'. If the encoded string contains
	// '+' or '/', it was encoded with standard base64, not base64url.
	if strings.ContainsAny(responseUserID, "+/") {
		t.Errorf("userID %q contains standard base64 characters (+/); expected base64url encoding", responseUserID)
	}

	t.Logf("invite-accepted identity verified: userID=%q (decoded: %s@%s)", responseUserID, decodedUserID, decodedIDP)
}

// decodeFederatedOpaqueUserID decodes the base64url userID and checks the
// payload has userID@idp structure.
func decodeFederatedOpaqueUserID(t *testing.T, responseUserID string) (string, string) {
	t.Helper()

	// userID must be valid base64url (padding omitted per RFC 4648 Sec 5)
	decoded, err := base64.RawURLEncoding.DecodeString(responseUserID)
	if err != nil {
		t.Fatalf("userID %q is not valid base64url: %v", responseUserID, err)
	}

	payload := string(decoded)

	idx := strings.LastIndex(payload, "@")
	if idx < 1 || idx == len(payload)-1 {
		t.Fatalf("decoded payload %q does not have valid userID@idp structure", payload)
	}

	return payload[:idx], payload[idx+1:]
}
