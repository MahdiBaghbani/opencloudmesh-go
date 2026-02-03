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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

// TestInviteAccepted_UserID_IsRevaStyleFederatedOpaqueID verifies that the
// /ocm/invite-accepted endpoint returns userID as a Reva-style federated
// opaque ID (base64url-padded encoding of userID@idp), not the old format
// (base64std(userID)@provider).
func TestInviteAccepted_UserID_IsRevaStyleFederatedOpaqueID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := harness.StartTestServer(t)
	defer ts.Stop(t)

	d := deps.GetDeps()
	localProvider := d.LocalProviderFQDN

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
		RecipientProvider: "remote.example.com",
		Token:             "identity-test-token",
		UserID:            "remote-user@remote.example.com",
		Email:             "remote@example.com",
		Name:              "Remote User",
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	resp, err := http.Post(ts.BaseURL+"/ocm/invite-accepted", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /ocm/invite-accepted failed: %v", err)
	}
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

	// --- Assertion 2: userID must be valid padded base64url ---
	decoded, err := base64.URLEncoding.DecodeString(response.UserID)
	if err != nil {
		t.Fatalf("userID %q is not valid padded base64url: %v", response.UserID, err)
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
