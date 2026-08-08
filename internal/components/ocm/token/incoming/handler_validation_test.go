// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestHandler_MissingFields(t *testing.T) {
	t.Parallel()
	shareRepo := tsrepos.OpenMemory(t).OutgoingShares
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com")

	tests := []struct {
		name string
		form url.Values
	}{
		{"missing grant_type", url.Values{"client_id": {"x"}, "code": {"y"}}},
		{"missing client_id", url.Values{"grant_type": {"authorization_code"}, "code": {"y"}}},
		{"missing code", url.Values{"grant_type": {"authorization_code"}, "client_id": {"x"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/token", strings.NewReader(tt.form.Encode()))
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

			if resp.Error != token.ErrorInvalidRequest {
				t.Errorf("expected error %q, got %q", token.ErrorInvalidRequest, resp.Error)
			}
		})
	}
}

// assertTokenFormRejected posts one urlencoded token form to a fresh handler
// and asserts the response is 400 carrying wantError.
func assertTokenFormRejected(t *testing.T, form url.Values, wantError string) {
	t.Helper()

	shareRepo := tsrepos.OpenMemory(t).OutgoingShares
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com")

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

	if resp.Error != wantError {
		t.Errorf("expected error %q, got %q", wantError, resp.Error)
	}
}

func TestHandler_InvalidGrantType(t *testing.T) {
	t.Parallel()

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "x")
	form.Set("code", "y")

	assertTokenFormRejected(t, form, token.ErrorUnsupportedGrantType)
}

// TestHandler_UnsupportedGrantType_Rejected proves the strict token contract
// rejects unknown grant types with unsupported_grant_type.
func TestHandler_UnsupportedGrantType_Rejected(t *testing.T) {
	t.Parallel()
	shareRepo := tsrepos.OpenMemory(t).OutgoingShares
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com")

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "receiver.example.com")
	form.Set("code", "secret-code")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	handler.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp token.OAuthError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if resp.Error != token.ErrorUnsupportedGrantType {
		t.Errorf("expected error %q, got %q", token.ErrorUnsupportedGrantType, resp.Error)
	}
}

// TestHandler_JSONBody_Rejected proves JSON token request bodies are rejected.
func TestHandler_JSONBody_Rejected(t *testing.T) {
	t.Parallel()
	shareRepo := tsrepos.OpenMemory(t).OutgoingShares
	tokenStore := token.NewMemoryTokenStore()
	handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com")

	body := `{"grant_type":"authorization_code","client_id":"receiver.example.com","code":"secret-code"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/token", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	handler.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp token.OAuthError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if resp.Error != token.ErrorInvalidRequest {
		t.Errorf("expected error %q, got %q", token.ErrorInvalidRequest, resp.Error)
	}
}

func TestHandler_ContentTypeValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		contentType        string
		omitContentType    bool
		wantStatus         int
		wantInvalidRequest bool
	}{
		{
			name:        "canonical form urlencoded",
			contentType: "application/x-www-form-urlencoded",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "form urlencoded with charset",
			contentType: "application/x-www-form-urlencoded; charset=utf-8",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "mixed case media type",
			contentType: "Application/x-www-Form-Urlencoded",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "upper case media type",
			contentType: "APPLICATION/X-WWW-FORM-URLENCODED",
			wantStatus:  http.StatusOK,
		},
		{
			name:               "omitted content type header",
			omitContentType:    true,
			wantStatus:         http.StatusBadRequest,
			wantInvalidRequest: true,
		},
		{
			name:               "text plain",
			contentType:        "text/plain",
			wantStatus:         http.StatusBadRequest,
			wantInvalidRequest: true,
		},
		{
			name:               "application json",
			contentType:        "application/json",
			wantStatus:         http.StatusBadRequest,
			wantInvalidRequest: true,
		},
		{
			name:               "bogus form urlencoded suffix",
			contentType:        "application/x-www-form-urlencoded-bogus",
			wantStatus:         http.StatusBadRequest,
			wantInvalidRequest: true,
		},
		{
			name:               "malformed charset parameter",
			contentType:        "application/x-www-form-urlencoded; charset=",
			wantStatus:         http.StatusBadRequest,
			wantInvalidRequest: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			shareRepo := tsrepos.OpenMemory(t).OutgoingShares
			tokenStore := token.NewMemoryTokenStore()
			handler := tokenincoming.NewHandler(shareRepo, tokenStore, enabledSettings(), enabledCodeFlow(), "https://local.example.com")

			sharedSecret := "content-type-secret-" + tt.name
			if tt.wantStatus == http.StatusOK {
				share := &sharesoutgoing.OutgoingShare{
					ProviderID:   "provider-content-type",
					WebDAVID:     "webdav-content-type",
					SharedSecret: sharedSecret,
					ReceiverHost: "receiver.example.com",
					LocalPath:    "/tmp/test.txt",
				}
				if err := shareRepo.Create(context.Background(), share); err != nil {
					t.Fatalf("Create: %v", err)
				}
			}

			form := url.Values{}
			form.Set("grant_type", "authorization_code")
			form.Set("client_id", "receiver.example.com")

			if tt.wantStatus == http.StatusOK {
				form.Set("code", sharedSecret)
			} else {
				form.Set("code", "arbitrary-code")
			}

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/token", strings.NewReader(form.Encode()))
			if !tt.omitContentType {
				req.Header.Set("Content-Type", tt.contentType)
			}

			w := httptest.NewRecorder()
			handler.HandleToken(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("expected %d, got %d: %s", tt.wantStatus, w.Code, w.Body.String())
			}

			if tt.wantInvalidRequest {
				var resp token.OAuthError
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				if resp.Error != token.ErrorInvalidRequest {
					t.Errorf("expected error %q, got %q", token.ErrorInvalidRequest, resp.Error)
				}

				return
			}

			var resp token.TokenResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if resp.AccessToken == "" {
				t.Error("access_token is empty")
			}
		})
	}
}
