// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ocm

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestService_SharesRequireVerifiedSignature(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputsWithOutgoingShareRepo(t), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodPost,
		"/shares",
		bytes.NewBufferString(`{"shareWith":"user@remote.example","name":"test","providerId":"provider-123","owner":"owner@remote.example","sender":"sender@remote.example","shareType":"user","resourceType":"file","protocol":{"name":"webdav","options":{"sharedSecret":"secret"}}}`),
	)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected unsigned share to be rejected, got %d: %s", w.Code, w.Body.String())
	}
}

func TestService_InviteAcceptedRequireVerifiedSignature(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputsWithOutgoingShareRepo(t), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodPost,
		"/invite-accepted",
		bytes.NewBufferString(`{"recipientProvider":"remote.example","token":"invite-token","userID":"user-1","email":"user@remote.example","name":"Remote User"}`),
	)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected unsigned invite-accepted to be rejected, got %d: %s", w.Code, w.Body.String())
	}
}

func TestService_SignedTokenExchangePropagatesVerifiedIdentity(t *testing.T) {
	const (
		clientHost   = "receiver.example.com"
		sharedSecret = "signed-token-secret"
	)

	signer, pd := hostSigningFixture(t, clientHost)

	inputs, spyStore, shareRepo := setupSignedTokenServiceInputs(t, pd)
	if err := shareRepo.Create(context.Background(), &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-signed-token",
		WebDAVID:     "webdav-signed-token",
		SharedSecret: sharedSecret,
		ReceiverHost: clientHost,
		LocalPath:    "/tmp/signed-token.txt",
	}); err != nil {
		t.Fatalf("create outgoing share: %v", err)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(inputs, map[string]any{}, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	form := "grant_type=authorization_code&client_id=" + clientHost + "&code=" + sharedSecret
	body := []byte(form)
	origin := config.DevConfig().PublicOrigin
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, origin+"/token", bytes.NewReader(body))
	req.Host = "localhost:9200"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("sign request: %v", err)
	}

	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected signed token exchange to succeed, got %d: %s", w.Code, w.Body.String())
	}

	var resp token.TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	if resp.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}

	if spyStore.captured == nil {
		t.Fatal("expected token store to observe authenticated peer identity")
	}

	if !spyStore.captured.Authenticated {
		t.Fatal("expected authenticated peer identity from signature middleware")
	}

	if spyStore.captured.AuthorityForCompare != clientHost {
		t.Fatalf("AuthorityForCompare = %q, want %q", spyStore.captured.AuthorityForCompare, clientHost)
	}
}

func TestService_TokenRequireVerifiedSignature(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputsWithOutgoingShareRepo(t), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	form := "grant_type=authorization_code&client_id=receiver.example.com&code=secret-code"
	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodPost,
		"/token",
		bytes.NewBufferString(form),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected unsigned token exchange to be rejected, got %d: %s", w.Code, w.Body.String())
	}
}
