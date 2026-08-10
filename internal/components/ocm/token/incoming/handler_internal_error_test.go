// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
)

type failingTokenStore struct {
	inner token.TokenStore
}

func (s *failingTokenStore) Store(_ context.Context, _ *token.IssuedToken) error {
	return errors.New("store failed")
}

func (s *failingTokenStore) Get(ctx context.Context, accessToken string) (*token.IssuedToken, error) {
	issued, err := s.inner.Get(ctx, accessToken)
	if err != nil {
		return issued, fmt.Errorf("ocm: get token: %w", err)
	}

	return issued, nil
}

func (s *failingTokenStore) Delete(ctx context.Context, accessToken string) error {
	if err := s.inner.Delete(ctx, accessToken); err != nil {
		return fmt.Errorf("ocm: delete token: %w", err)
	}

	return nil
}

func (s *failingTokenStore) CleanExpired(ctx context.Context) error {
	if err := s.inner.CleanExpired(ctx); err != nil {
		return fmt.Errorf("ocm: clean expired tokens: %w", err)
	}

	return nil
}

func enabledSettings() *TokenExchangeSettings {
	s := &TokenExchangeSettings{}
	s.ApplyDefaults()

	return s
}

func enabledCodeFlow() *policy.CodeFlow {
	return policy.NewCodeFlow()
}

func TestTokenExchange_InternalError_ReturnsServerError(t *testing.T) {
	t.Parallel()

	t.Run("nil outgoing repo", func(t *testing.T) {
		t.Parallel()

		handler := NewHandler(nil, token.NewMemoryTokenStore(), enabledSettings(), enabledCodeFlow(), "https://local.example.com")
		w := postTokenExchange(t, handler, tokenExchangeForm(t, "unused-secret"))

		assertOAuthServerError(t, w)
	})

	t.Run("non-positive token TTL", func(t *testing.T) {
		t.Parallel()

		shareRepo := tsrepos.OpenMemory(t).OutgoingShares
		secret := seedTokenExchangeShare(t, shareRepo)
		handler := NewHandler(shareRepo, token.NewMemoryTokenStore(), enabledSettings(), enabledCodeFlow(), "https://local.example.com")
		handler.tokenTTL = 0

		w := postTokenExchange(t, handler, tokenExchangeForm(t, secret))
		assertOAuthServerError(t, w)
	})

	t.Run("access token generation failure", func(t *testing.T) {
		t.Parallel()

		shareRepo := tsrepos.OpenMemory(t).OutgoingShares
		secret := seedTokenExchangeShare(t, shareRepo)
		handler := NewHandler(shareRepo, token.NewMemoryTokenStore(), enabledSettings(), enabledCodeFlow(), "https://local.example.com")
		handler.generateAccessTokenFn = func() (string, error) {
			return "", errors.New("generation failed")
		}

		w := postTokenExchange(t, handler, tokenExchangeForm(t, secret))
		assertOAuthServerError(t, w)
	})

	t.Run("token storage failure", func(t *testing.T) {
		t.Parallel()

		shareRepo := tsrepos.OpenMemory(t).OutgoingShares
		secret := seedTokenExchangeShare(t, shareRepo)
		inner := token.NewMemoryTokenStore()
		handler := NewHandler(shareRepo, &failingTokenStore{inner: inner}, enabledSettings(), enabledCodeFlow(), "https://local.example.com")

		w := postTokenExchange(t, handler, tokenExchangeForm(t, secret))
		assertOAuthServerError(t, w)
	})

	t.Run("disabled returns 501 not_implemented", func(t *testing.T) {
		t.Parallel()

		shareRepo := tsrepos.OpenMemory(t).OutgoingShares
		disabledSettings := &TokenExchangeSettings{}
		disabledSettings.ApplyDefaults()
		handler := NewHandler(shareRepo, token.NewMemoryTokenStore(), disabledSettings, nil, "https://local.example.com")

		w := postTokenExchange(t, handler, tokenExchangeForm(t, "unused-secret"))
		assertOAuthNotImplemented(t, w)
	})
}

func seedTokenExchangeShare(t *testing.T, repo sharesoutgoing.OutgoingShareRepo) string {
	t.Helper()

	const secret = "internal-error-secret"

	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-internal-error",
		WebDAVID:     "webdav-internal-error",
		SharedSecret: secret,
		ReceiverHost: "receiver.example.com",
		LocalPath:    "/tmp/test.txt",
	}
	if err := repo.Create(context.Background(), share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	return secret
}

func tokenExchangeForm(t *testing.T, code string) url.Values {
	t.Helper()

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "receiver.example.com")
	form.Set("code", code)

	return form
}

func postTokenExchange(t *testing.T, handler *Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	handler.HandleToken(w, req)

	return w
}

func assertOAuthServerError(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}

	var resp token.OAuthError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if resp.Error != token.ErrorServerError {
		t.Errorf("expected error %q, got %q", token.ErrorServerError, resp.Error)
	}
}

func assertOAuthNotImplemented(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", w.Code, w.Body.String())
	}

	var resp token.OAuthError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if resp.Error != "not_implemented" {
		t.Errorf("expected error %q, got %q", "not_implemented", resp.Error)
	}
}
