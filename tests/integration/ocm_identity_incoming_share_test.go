// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

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
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// This test targets recipient identity resolution, not token-exchange
	// policy. The receiver requires token exchange, so the request carries
	// the must-exchange-token requirement and the peer is a discoverable,
	// token-exchange-capable receiver.
	ts := harness.StartTestServerWithConfig(t, disableMustInvite)
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

	body := tshttp.MustMarshalJSON(t, reqBody)

	resp := postSignedJSON(t, ts.BaseURL+"/ocm/shares", body, peer.signer) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusCreated {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

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

	body := tshttp.MustMarshalJSON(t, reqBody)

	resp := postSignedJSON(t, ts.BaseURL+"/ocm/shares", body, peer.signer) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

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
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// This test targets owner/sender address acceptance, not token-exchange
	// policy. The receiver requires token exchange, so the request carries
	// the must-exchange-token requirement and the peer is a discoverable,
	// token-exchange-capable receiver.
	ts := harness.StartTestServerWithConfig(t, disableMustInvite)
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

	body := tshttp.MustMarshalJSON(t, reqBody)

	resp := postSignedJSON(t, ts.BaseURL+"/ocm/shares", body, peer.signer) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusCreated {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

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
