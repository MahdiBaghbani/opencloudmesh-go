// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"context"
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

func seedExchangeShare(t *testing.T, repo sharesoutgoing.OutgoingShareRepo) *sharesoutgoing.OutgoingShare {
	t.Helper()

	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-obs",
		WebDAVID:     "webdav-obs",
		SharedSecret: "secret-obs",
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
	}
	if err := repo.Create(context.Background(), share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	return share
}

func exchangeRequest(t *testing.T, code string) *http.Request {
	t.Helper()

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "receiver.example.com")
	form.Set("code", code)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req
}

func TestHandler_ExchangeObserverInvokedOnSuccess(t *testing.T) {
	t.Parallel()

	shareRepo := tsrepos.OpenMemory(t).OutgoingShares
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com")

	share := seedExchangeShare(t, shareRepo)

	var observed *sharesoutgoing.OutgoingShare

	handler.SetExchangeObserver(func(_ context.Context, s *sharesoutgoing.OutgoingShare) error {
		observed = s

		return nil
	})

	w := httptest.NewRecorder()
	handler.HandleToken(w, exchangeRequest(t, "secret-obs"))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if observed == nil || observed.ShareID != share.ShareID {
		t.Fatalf("observer share = %v, want the exchanged share %s", observed, share.ShareID)
	}
}

func TestHandler_ExchangeObserverErrorSuppressesSuccess(t *testing.T) {
	t.Parallel()

	shareRepo := tsrepos.OpenMemory(t).OutgoingShares
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com")

	seedExchangeShare(t, shareRepo)

	handler.SetExchangeObserver(func(_ context.Context, _ *sharesoutgoing.OutgoingShare) error {
		return errors.New("storage unavailable")
	})

	w := httptest.NewRecorder()
	handler.HandleToken(w, exchangeRequest(t, "secret-obs"))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}

	if !strings.Contains(w.Body.String(), token.ErrorServerError) {
		t.Errorf("body = %q, want a %q error", w.Body.String(), token.ErrorServerError)
	}
}

func TestHandler_ExchangeObserverNotInvokedOnInvalidCode(t *testing.T) {
	t.Parallel()

	shareRepo := tsrepos.OpenMemory(t).OutgoingShares
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com")

	seedExchangeShare(t, shareRepo)

	called := false

	handler.SetExchangeObserver(func(_ context.Context, _ *sharesoutgoing.OutgoingShare) error {
		called = true

		return nil
	})

	w := httptest.NewRecorder()
	handler.HandleToken(w, exchangeRequest(t, "wrong-secret"))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	if called {
		t.Error("observer must not run when the exchange never verified a share")
	}
}

func TestHandler_NoExchangeObserverKeepsPlainPath(t *testing.T) {
	t.Parallel()

	shareRepo := tsrepos.OpenMemory(t).OutgoingShares
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com")

	seedExchangeShare(t, shareRepo)

	w := httptest.NewRecorder()
	handler.HandleToken(w, exchangeRequest(t, "secret-obs"))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
