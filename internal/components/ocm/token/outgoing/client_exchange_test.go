// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outgoing_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

func TestClient_Exchange_Success_LowercaseBearerTokenType(t *testing.T) {
	server := newTokenTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "test-access-token",
			TokenType:   "bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	result, err := exchangeOnServer(t, server.URL, "test-secret")
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if result.AccessToken != "test-access-token" {
		t.Errorf("expected access_token 'test-access-token', got %s", result.AccessToken)
	}
	if result.TokenType != "bearer" {
		t.Errorf("expected token_type 'bearer', got %s", result.TokenType)
	}
}

func TestClient_Exchange_Success(t *testing.T) {
	server := newTokenTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("expected form-urlencoded, got %s", r.Header.Get("Content-Type"))
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm failed: %v", err)
		}
		if got := r.FormValue("grant_type"); got != "authorization_code" {
			t.Errorf("grant_type = %q, want %q", got, "authorization_code")
		}
		if got := r.FormValue("client_id"); got != "my-instance.example.com" {
			t.Errorf("client_id = %q, want %q", got, "my-instance.example.com")
		}
		if got := r.FormValue("code"); got != "test-secret" {
			t.Errorf("code = %q, want %q", got, "test-secret")
		}

		// Verify signature header exists
		if r.Header.Get("Signature") == "" {
			t.Error("expected Signature header")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "test-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF: config.SSRFConfig{Mode: "off"},
	}, nil))

	client := tokenoutgoing.NewClient(httpClient, &mockSigner{}, "my-instance.example.com")

	result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		SharedSecret:  "test-secret",
	})

	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if result.AccessToken != "test-access-token" {
		t.Errorf("expected access_token 'test-access-token', got %s", result.AccessToken)
	}
	if result.TokenType != "Bearer" {
		t.Errorf("expected token_type 'Bearer', got %s", result.TokenType)
	}
}

func TestClient_Exchange_NoSignerSkipsTokenEndpoint(t *testing.T) {
	tokenEndpointCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenEndpointCalled = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "should-not-be-returned",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF:             config.SSRFConfig{Mode: "off"},
		MaxResponseBytes: config.DefaultMaxResponseBytes,
	}, nil))

	client := tokenoutgoing.NewClient(httpClient, nil, "local.example.com")

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		SharedSecret:  "test-secret",
	})
	if err == nil {
		t.Fatal("expected signing failure without signer")
	}

	var ce *reason.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}
	if ce.ReasonCode != reason.ReasonSignatureRequired {
		t.Fatalf("expected reason %q, got %q (cause=%v err=%v)", reason.ReasonSignatureRequired, ce.ReasonCode, ce.Cause, err)
	}
	if tokenEndpointCalled {
		t.Fatal("token endpoint should not be called when signing precondition fails")
	}
}

func TestClient_Exchange_SignFailureFailClosed(t *testing.T) {
	tokenEndpointCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenEndpointCalled = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "should-not-be-returned",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF:             config.SSRFConfig{Mode: "off"},
		MaxResponseBytes: config.DefaultMaxResponseBytes,
	}, nil))

	client := tokenoutgoing.NewClient(httpClient, &mockSigner{failSign: true}, "local.example.com")

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		SharedSecret:  "test-secret",
	})
	if err == nil {
		t.Fatal("expected failure when signing fails")
	}

	var ce *reason.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}
	if ce.ReasonCode != reason.ReasonSignatureInvalid {
		t.Fatalf("expected reason %q, got %q (cause=%v err=%v)", reason.ReasonSignatureInvalid, ce.ReasonCode, ce.Cause, err)
	}
	if tokenEndpointCalled {
		t.Fatal("token endpoint should not be called when signing fails")
	}
}

func TestClient_Exchange_SignedRejection401EmptyBodySingleAttempt(t *testing.T) {
	var tokenHits atomic.Int32
	server := newTokenTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHits.Add(1)
		if r.URL.Path != "/ocm/token" {
			t.Errorf("request path = %q, want %q", r.URL.Path, "/ocm/token")
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF: config.SSRFConfig{Mode: "off"},
	}, nil))

	client := tokenoutgoing.NewClient(httpClient, &mockSigner{}, "my-instance.example.com")

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL + "/ocm/token",
		SharedSecret:  "test-secret",
	})
	if err == nil {
		t.Fatal("expected failure for signed 401 with empty body")
	}
	var ce *reason.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}
	if ce.ReasonCode != reason.ReasonSignatureRequired {
		t.Fatalf("expected reason %q, got %q", reason.ReasonSignatureRequired, ce.ReasonCode)
	}
	if tokenHits.Load() != 1 {
		t.Fatalf("hits = %d, want 1", tokenHits.Load())
	}
}

func TestClient_Exchange_RejectsMalformedJSONBody(t *testing.T) {
	server := newTokenTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{not valid json"))
	}))
	defer server.Close()

	_, err := exchangeOnServer(t, server.URL+"/ocm/token", "test-secret")
	assertTokenInvalidFormat(t, err)
}

func TestClient_Exchange_SignedRejection401OAuthErrorSingleAttempt(t *testing.T) {
	var tokenHits atomic.Int32
	server := newTokenTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(token.OAuthError{
			Error:            token.ErrorUnauthorized,
			ErrorDescription: "signature required",
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF: config.SSRFConfig{Mode: "off"},
	}, nil))

	client := tokenoutgoing.NewClient(httpClient, &mockSigner{}, "my-instance.example.com")

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		SharedSecret:  "test-secret",
	})
	if err == nil {
		t.Fatal("expected failure for signed 401 with OAuth error body")
	}
	if tokenHits.Load() != 1 {
		t.Fatalf("hits = %d, want 1", tokenHits.Load())
	}
	var ce *reason.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}
	if ce.ReasonCode != reason.ReasonSignatureRequired {
		t.Fatalf("expected reason %q, got %q", reason.ReasonSignatureRequired, ce.ReasonCode)
	}
}

func TestClient_Exchange_RejectsOversizeResponse(t *testing.T) {
	oversizeBody := make([]byte, config.DefaultMaxResponseBytes+1)
	for i := range oversizeBody {
		oversizeBody[i] = 'x'
	}

	server := newTokenTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(oversizeBody)
	}))
	defer server.Close()

	_, err := exchangeOnServer(t, server.URL, "test-secret")
	assertTokenInvalidFormat(t, err)
}

func TestClient_Exchange_RejectsNonJSONContentType(t *testing.T) {
	server := newTokenTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	_, err := exchangeOnServer(t, server.URL, "test-secret")
	assertTokenInvalidFormat(t, err)
}

func TestClient_Exchange_RejectsEmptyAccessToken(t *testing.T) {
	server := newTokenTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	_, err := exchangeOnServer(t, server.URL, "test-secret")
	assertTokenInvalidFormat(t, err)
}

func TestClient_Exchange_RejectsNonBearerTokenType(t *testing.T) {
	server := newTokenTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "tok",
			TokenType:   "MAC",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	_, err := exchangeOnServer(t, server.URL, "test-secret")
	assertTokenInvalidFormat(t, err)
}

func TestClient_Exchange_RejectsNonPositiveExpiresIn(t *testing.T) {
	server := newTokenTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "tok",
			TokenType:   "Bearer",
			ExpiresIn:   0,
		})
	}))
	defer server.Close()

	_, err := exchangeOnServer(t, server.URL, "test-secret")
	assertTokenInvalidFormat(t, err)
}

func exchangeOnServer(t *testing.T, serverURL, secret string) (*tokenoutgoing.ExchangeResult, error) {
	t.Helper()
	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF: config.SSRFConfig{Mode: "off"},
	}, nil))
	client := tokenoutgoing.NewClient(httpClient, &mockSigner{}, "my-instance.example.com")
	return client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: serverURL,
		SharedSecret:  secret,
	})
}

func assertTokenInvalidFormat(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *reason.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}
	if ce.ReasonCode != reason.ReasonTokenInvalidFormat {
		t.Fatalf("expected reason %q, got %q", reason.ReasonTokenInvalidFormat, ce.ReasonCode)
	}
}
