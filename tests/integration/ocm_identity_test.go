// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func postSignedJSON(t *testing.T, targetURL string, body []byte, signer *crypto.RFC9421Signer) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to build signed request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if err := signer.Sign(req); err != nil {
		t.Fatalf("failed to sign request: %v", err)
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

	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	resp := postSignedJSON(t, ts.BaseURL+"/ocm/invite-accepted", body, peer.signer)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(respBody))
	}

	var response spec.InviteAcceptedResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// --- Assertion 1: userID must match EncodeFederatedOpaqueID output ---
	expectedUserID := address.EncodeFederatedOpaqueID(localUser.ID, localProvider)
	if response.UserID != expectedUserID {
		t.Errorf("userID = %q, want %q", response.UserID, expectedUserID)
	}

	// --- Assertion 2: userID must be valid base64url (padding omitted per RFC 4648 Sec 5) ---
	decoded, err := base64.RawURLEncoding.DecodeString(response.UserID)
	if err != nil {
		t.Fatalf("userID %q is not valid base64url: %v", response.UserID, err)
	}

	// --- Assertion 3: decoded payload must be userID@idp ---
	payload := string(decoded)

	idx := strings.LastIndex(payload, "@")
	if idx < 1 || idx == len(payload)-1 {
		t.Fatalf("decoded payload %q does not have valid userID@idp structure", payload)
	}

	decodedUserID := payload[:idx]
	decodedIDP := payload[idx+1:]

	if decodedUserID != localUser.ID {
		t.Errorf("decoded userID = %q, want %q", decodedUserID, localUser.ID)
	}

	if decodedIDP != localProvider {
		t.Errorf("decoded idp = %q, want %q", decodedIDP, localProvider)
	}

	// --- Assertion 4: userID must NOT be in the old format (base64std(uid)@provider) ---
	oldFormatSuffix := "@" + localProvider
	if strings.HasSuffix(response.UserID, oldFormatSuffix) {
		t.Errorf("userID %q appears to use old OCM address format (base64std(uid)@provider); "+
			"invite userID should be an opaque ID without @provider suffix", response.UserID)
	}

	// --- Assertion 5: userID must NOT contain standard base64 chars that differ from base64url ---
	// base64url uses '-' and '_' instead of '+' and '/'. If the encoded string contains
	// '+' or '/', it was encoded with standard base64, not base64url.
	if strings.ContainsAny(response.UserID, "+/") {
		t.Errorf("userID %q contains standard base64 characters (+/); expected base64url encoding", response.UserID)
	}

	t.Logf("invite-accepted identity verified: userID=%q (decoded: %s@%s)", response.UserID, decodedUserID, decodedIDP)
}

// --- Share creation identity tests ---
//
// These tests verify inbound share creation through the full server stack.
// They exercise the federated opaque ID decode fallback and
// Reva-style OCM address acceptance for owner/sender.
//
// Outbound share identity encoding (owner/sender emission via
// FormatOutgoingOCMAddressFromUserID) is covered by unit tests in
// internal/components/api/outgoing/shares/handler_test.go.
//
// Token exchange grant_type coverage lives in token_exchange_test.go
// (authorization_code + invalid grant_type rejection).

// TestIncomingShare_FederatedOpaqueID_ResolvesViaDecodeFallback verifies that
// POST /ocm/shares with a Reva-style base64url-encoded shareWith identifier
// resolves the local recipient through the federated opaque ID decode fallback.
func TestIncomingShare_FederatedOpaqueID_ResolvesViaDecodeFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// This test targets recipient identity resolution, not token-exchange
	// policy. The receiver requires token exchange, so the request carries
	// the must-exchange-token requirement and the peer is a discoverable,
	// token-exchange-capable receiver.
	ts := harness.StartTestServer(t)
	defer ts.Stop(t)

	peer := startStrictCodeFlowReceiver(t)
	defer peer.Close()

	d := ts.Deps
	localProvider := d.LocalIdentity.ProviderDomain

	// Seed a local user (the share recipient)
	shareUser := &identity.User{
		ID:          "share-decode-user-uuid",
		Username:    "sharedecode",
		Email:       "sharedecode@localhost",
		DisplayName: "Share Decode User",
	}
	if err := d.PartyRepo.Create(context.Background(), shareUser); err != nil {
		t.Fatalf("failed to seed local user: %v", err)
	}

	// Build shareWith using Reva-style federated opaque ID as the identifier.
	// The encoded identifier won't match by raw ID, username, or email,
	// so the decode fallback must fire to resolve the recipient.
	encodedID := address.EncodeFederatedOpaqueID(shareUser.ID, localProvider)
	shareWith := encodedID + "@" + localProvider

	// Build Reva-style owner/sender OCM addresses for the signed peer.
	remoteProvider := peer.peerDomain
	owner := address.FormatOutgoingOCMAddressFromUserID("remote-owner-id", remoteProvider)
	sender := address.FormatOutgoingOCMAddressFromUserID("remote-sender-id", remoteProvider)

	reqBody := spec.NewShareRequest{
		ShareWith:    shareWith,
		Name:         "test-federated-share.txt",
		ProviderID:   "federated-decode-test-001",
		Owner:        owner,
		Sender:       sender,
		ShareType:    "user",
		ResourceType: "file",
		Protocol: spec.Protocol{
			Name: "webdav",
			WebDAV: &spec.WebDAVProtocol{
				URI:          "federated-share-uri",
				SharedSecret: "secret-abc",
				Permissions:  []string{"read"},
				Requirements: []string{spec.RequirementMustExchangeToken},
			},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	resp := postSignedJSON(t, ts.BaseURL+"/ocm/shares", body, peer.signer)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, string(respBody))
	}

	var shareResp spec.CreateShareResponse
	if err := json.NewDecoder(resp.Body).Decode(&shareResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// The decode fallback should have resolved the federated opaque ID to shareUser
	if shareResp.RecipientDisplayName != shareUser.DisplayName {
		t.Errorf("recipientDisplayName = %q, want %q", shareResp.RecipientDisplayName, shareUser.DisplayName)
	}

	// Verify the shareWith identifier is valid base64url (padding omitted per RFC 4648 Sec 5)
	decoded, err := base64.RawURLEncoding.DecodeString(encodedID)
	if err != nil {
		t.Errorf("encoded identifier %q is not valid base64url: %v", encodedID, err)
	}

	// Verify the decoded payload has userID@idp structure
	payload := string(decoded)

	idx := strings.LastIndex(payload, "@")
	if idx < 1 || idx == len(payload)-1 {
		t.Fatalf("decoded payload %q does not have valid userID@idp structure", payload)
	}

	if payload[:idx] != shareUser.ID {
		t.Errorf("decoded userID = %q, want %q", payload[:idx], shareUser.ID)
	}

	if payload[idx+1:] != localProvider {
		t.Errorf("decoded idp = %q, want %q", payload[idx+1:], localProvider)
	}

	t.Logf("share created via decode fallback: shareWith=%q, recipient=%q", shareWith, shareResp.RecipientDisplayName)
}

// TestIncomingShare_FederatedOpaqueID_IDPMismatch_Rejected verifies that
// POST /ocm/shares rejects a share where the decoded federated opaque ID's
// IDP does not match the local provider.
func TestIncomingShare_FederatedOpaqueID_IDPMismatch_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := harness.StartTestServer(t)
	defer ts.Stop(t)

	peer := startStrictCodeFlowReceiver(t)
	defer peer.Close()

	d := ts.Deps
	localProvider := d.LocalIdentity.ProviderDomain

	// Seed a local user
	shareUser := &identity.User{
		ID:          "idp-mismatch-user-uuid",
		Username:    "idpmismatch",
		Email:       "idpmismatch@localhost",
		DisplayName: "IDP Mismatch User",
	}
	if err := d.PartyRepo.Create(context.Background(), shareUser); err != nil {
		t.Fatalf("failed to seed local user: %v", err)
	}

	// Encode with WRONG IDP -- the user exists locally, but the encoded IDP
	// doesn't match the local provider, so the decode fallback must reject.
	wrongIDP := "wrong.example.com"
	encodedID := address.EncodeFederatedOpaqueID(shareUser.ID, wrongIDP)
	shareWith := encodedID + "@" + localProvider

	reqBody := spec.NewShareRequest{
		ShareWith:    shareWith,
		Name:         "test-idp-mismatch.txt",
		ProviderID:   "idp-mismatch-test-001",
		Owner:        address.FormatOutgoingOCMAddressFromUserID("owner", peer.peerDomain),
		Sender:       address.FormatOutgoingOCMAddressFromUserID("sender", peer.peerDomain),
		ShareType:    "user",
		ResourceType: "file",
		Protocol: spec.Protocol{
			Name: "webdav",
			WebDAV: &spec.WebDAVProtocol{
				URI:          "mismatch-uri",
				SharedSecret: "secret-xyz",
				Permissions:  []string{"read"},
				Requirements: []string{spec.RequirementMustExchangeToken},
			},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	resp := postSignedJSON(t, ts.BaseURL+"/ocm/shares", body, peer.signer)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400 for IDP mismatch, got %d: %s", resp.StatusCode, string(respBody))
	}

	var errResp spec.OCMErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if errResp.Message != "RECIPIENT_NOT_FOUND" {
		t.Errorf("message = %q, want RECIPIENT_NOT_FOUND", errResp.Message)
	}

	t.Logf("share correctly rejected: IDP mismatch (encoded IDP=%q, local=%q)", wrongIDP, localProvider)
}

// TestIncomingShare_RevaStyleOwnerSender_Accepted verifies that inbound shares
// with Reva-style base64url owner/sender addresses are accepted.
func TestIncomingShare_RevaStyleOwnerSender_Accepted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// This test targets owner/sender address acceptance, not token-exchange
	// policy. The receiver requires token exchange, so the request carries
	// the must-exchange-token requirement and the peer is a discoverable,
	// token-exchange-capable receiver.
	ts := harness.StartTestServer(t)
	defer ts.Stop(t)

	peer := startStrictCodeFlowReceiver(t)
	defer peer.Close()

	d := ts.Deps
	localProvider := d.LocalIdentity.ProviderDomain

	// Seed a local user (the share recipient)
	shareUser := &identity.User{
		ID:          "fed-opaque-user-uuid",
		Username:    "fedopaque",
		Email:       "fedopaque@localhost",
		DisplayName: "Fed Opaque User",
	}
	if err := d.PartyRepo.Create(context.Background(), shareUser); err != nil {
		t.Fatalf("failed to seed local user: %v", err)
	}

	// Use the user's canonical ID as shareWith (simple resolution path)
	shareWith := shareUser.ID + "@" + localProvider

	// Build Reva-style owner and sender: base64url(uid@provider)@provider
	remoteProvider := peer.peerDomain
	owner := address.FormatOutgoingOCMAddressFromUserID("einstein", remoteProvider)
	sender := address.FormatOutgoingOCMAddressFromUserID("einstein", remoteProvider)

	reqBody := spec.NewShareRequest{
		ShareWith:         shareWith,
		Name:              "fed-opaque-share.txt",
		ProviderID:        "fed-opaque-test-001",
		Owner:             owner,
		Sender:            sender,
		OwnerDisplayName:  "Albert Einstein",
		SenderDisplayName: "Albert Einstein",
		ShareType:         "user",
		ResourceType:      "file",
		Protocol: spec.Protocol{
			Name: "webdav",
			WebDAV: &spec.WebDAVProtocol{
				URI:          "reva-share-uri",
				SharedSecret: "reva-secret",
				Permissions:  []string{"read"},
				Requirements: []string{spec.RequirementMustExchangeToken},
			},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	resp := postSignedJSON(t, ts.BaseURL+"/ocm/shares", body, peer.signer)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, string(respBody))
	}

	var shareResp spec.CreateShareResponse
	if err := json.NewDecoder(resp.Body).Decode(&shareResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if shareResp.RecipientDisplayName != shareUser.DisplayName {
		t.Errorf("recipientDisplayName = %q, want %q", shareResp.RecipientDisplayName, shareUser.DisplayName)
	}

	// Verify owner is a valid OCM address with a base64url-encoded identifier
	ownerIdent, ownerProvider, err := address.Parse(owner)
	if err != nil {
		t.Fatalf("failed to parse owner address: %v", err)
	}

	if ownerProvider != remoteProvider {
		t.Errorf("owner provider = %q, want %q", ownerProvider, remoteProvider)
	}

	if _, err := base64.RawURLEncoding.DecodeString(ownerIdent); err != nil {
		t.Errorf("owner identifier %q is not valid base64url: %v", ownerIdent, err)
	}

	t.Logf("reva-style owner/sender accepted: owner=%q", owner)
}
