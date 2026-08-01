// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tokenincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/incoming"
)

func TestHandler_InvalidCode(t *testing.T) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "receiver.example.com")
	form.Set("code", "nonexistent-secret")

	assertTokenFormRejected(t, form, token.ErrorInvalidGrant)
}

func TestHandler_ClientMismatch(t *testing.T) {
	shareRepo := tsrepos.OpenMemory(t).OutgoingShares
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com")

	// Create a share
	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-mismatch",
		WebDAVID:     "webdav-mismatch",
		SharedSecret: "secret-mismatch",
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
	}
	if err := shareRepo.Create(context.Background(), share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "wrong-receiver.example.com")
	form.Set("code", "secret-mismatch")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	handler.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var resp token.OAuthError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if resp.Error != token.ErrorInvalidClient {
		t.Errorf("expected error %q, got %q", token.ErrorInvalidClient, resp.Error)
	}
}

func TestTokenStore_Expiration(t *testing.T) {
	store := token.NewMemoryTokenStore()
	ctx := context.Background()

	// Store a token with very short TTL (already expired)
	expired := &token.IssuedToken{
		AccessToken: "expired-token",
		ShareID:     "share-1",
	}
	// Manually set to expired
	expired.ExpiresAt = expired.IssuedAt // already expired

	if err := store.Store(ctx, expired); err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Try to get it
	_, err := store.Get(ctx, "expired-token")
	if !errors.Is(err, token.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestGenerateAccessToken(t *testing.T) {
	token1, err := token.GenerateAccessToken()
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	token2, err := token.GenerateAccessToken()
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	if token1 == token2 {
		t.Error("generated tokens should be unique")
	}

	if len(token1) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("expected 64 char token, got %d", len(token1))
	}
}
