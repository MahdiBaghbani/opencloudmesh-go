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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

func TestClient_Exchange_Success_LowercaseBearerTokenType(t *testing.T) {
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	client := tokenoutgoing.NewClient(
		httpClient,
		dummyDiscClient(),
		&mockSigner{},
		makePolicy("strict", nil),
		"my-instance.example.com",
	)

	result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		PeerDomain:    "peer.example.com",
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

func TestClient_Exchange_RediscoveryFailureIsReturned(t *testing.T) {
	tokenEndpointCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			http.Error(w, "discovery unavailable", http.StatusServiceUnavailable)
		case "/ocm/token":
			tokenEndpointCalled = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(token.TokenResponse{
				AccessToken: "should-not-be-returned",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF: config.SSRFConfig{Mode: "off"},
	}, nil))

	client := tokenoutgoing.NewClient(
		httpClient,
		dummyDiscClient(),
		&mockSigner{},
		makePolicy("strict", nil),
		"my-instance.example.com",
	)

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL + "/ocm/token",
		PeerDomain:    "peer.example.com",
		SharedSecret:  "test-secret",
	})
	if err == nil {
		t.Fatal("expected rediscovery failure")
	}

	var ce *reason.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}
	if ce.ReasonCode != reason.ReasonDiscoveryFailed {
		t.Fatalf("expected reason %q, got %q", reason.ReasonDiscoveryFailed, ce.ReasonCode)
	}
	if tokenEndpointCalled {
		t.Fatal("token endpoint should not be called when rediscovery fails")
	}
}

func TestClient_Exchange_RediscoveryUsesTokenEndpointOrigin(t *testing.T) {
	tokenEndpointCalled := false
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(discovery.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      server.URL + "/ocm",
				Capabilities:  []string{"exchange-token"},
				Criteria:      []string{spec.CriteriaMustExchangeToken},
				TokenEndPoint: server.URL + "/token-exchange/v2",
				ResourceTypes: []discovery.ResourceType{
					{
						Name:       "file",
						ShareTypes: []string{"user"},
						Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm")},
					},
				},
			})
		case "/token-exchange/v2":
			tokenEndpointCalled = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(token.TokenResponse{
				AccessToken: "should-not-be-returned",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF:             config.SSRFConfig{Mode: "off"},
		MaxResponseBytes: config.DefaultMaxResponseBytes,
	}, nil))
	discClient := discovery.NewClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF:             config.SSRFConfig{Mode: "off"},
		MaxResponseBytes: config.DefaultMaxResponseBytes,
	}, nil), nil)

	client := tokenoutgoing.NewClient(
		httpClient,
		discClient,
		nil, // no signer
		makePolicy("strict", nil),
		"my-instance.example.com",
	)

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL + "/token-exchange/v2",
		PeerDomain:    "peer.example.com",
		SharedSecret:  "test-secret",
	})
	if err == nil {
		t.Fatal("expected signing failure for strict peer without signer")
	}

	var ce *reason.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}
	if ce.ReasonCode != reason.ReasonSignatureRequired {
		t.Fatalf("expected reason %q, got %q (cause=%v err=%v)", reason.ReasonSignatureRequired, ce.ReasonCode, ce.Cause, err)
	}
	if tokenEndpointCalled {
		t.Fatal("token endpoint should not be called when strict signing precondition fails")
	}
}

func TestClient_Exchange_RediscoveryFailureWithNonOCMPathIsReturned(t *testing.T) {
	tokenEndpointCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			http.Error(w, "discovery unavailable", http.StatusServiceUnavailable)
		case "/token-exchange/v2":
			tokenEndpointCalled = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(token.TokenResponse{
				AccessToken: "should-not-be-returned",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF:             config.SSRFConfig{Mode: "off"},
		MaxResponseBytes: config.DefaultMaxResponseBytes,
	}, nil))
	discClient := discovery.NewClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF:             config.SSRFConfig{Mode: "off"},
		MaxResponseBytes: config.DefaultMaxResponseBytes,
	}, nil), nil)

	client := tokenoutgoing.NewClient(
		httpClient,
		discClient,
		&mockSigner{},
		makePolicy("strict", nil),
		"my-instance.example.com",
	)

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL + "/token-exchange/v2",
		PeerDomain:    "peer.example.com",
		SharedSecret:  "test-secret",
	})
	if err == nil {
		t.Fatal("expected rediscovery failure")
	}

	var ce *reason.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}
	if ce.ReasonCode != reason.ReasonDiscoveryFailed {
		t.Fatalf("expected reason %q, got %q", reason.ReasonDiscoveryFailed, ce.ReasonCode)
	}
	if tokenEndpointCalled {
		t.Fatal("token endpoint should not be called when rediscovery fails")
	}
}

func TestClient_Exchange_SignedRejection401EmptyBodyNoUnsignedRetry(t *testing.T) {
	var tokenHits atomic.Int32
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	client := tokenoutgoing.NewClient(
		httpClient,
		dummyDiscClient(),
		&mockSigner{},
		makePolicy("strict", nil),
		"my-instance.example.com",
	)

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL + "/ocm/token",
		PeerDomain:    "peer.example.com",
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
		t.Fatalf("hits = %d, want 1 (no unsigned retry)", tokenHits.Load())
	}
}

func TestClient_Exchange_RejectsMalformedJSONBody(t *testing.T) {
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{not valid json"))
	}))
	defer server.Close()

	_, err := exchangeOnServer(t, server.URL+"/ocm/token", "test-secret")
	assertTokenInvalidFormat(t, err)
}

func TestClient_Exchange_SignedRejectionNoUnsignedRetry(t *testing.T) {
	var tokenHits atomic.Int32
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	client := tokenoutgoing.NewClient(
		httpClient,
		dummyDiscClient(),
		&mockSigner{},
		makePolicy("strict", nil),
		"my-instance.example.com",
	)

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		PeerDomain:    "peer.example.com",
		SharedSecret:  "test-secret",
	})
	if err == nil {
		t.Fatal("expected failure without unsigned retry")
	}
	if tokenHits.Load() != 1 {
		t.Fatalf("hits = %d, want 1 (no unsigned retry)", tokenHits.Load())
	}
	var ce *reason.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}
	if ce.ReasonCode != reason.ReasonSignatureRequired {
		t.Fatalf("expected reason %q, got %q", reason.ReasonSignatureRequired, ce.ReasonCode)
	}
}

func TestClient_Exchange_PeerMissingExchangeTokenCapability(t *testing.T) {
	tokenEndpointCalled := false
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(discovery.Discovery{
				Enabled:      true,
				APIVersion:   "1.4.0",
				EndPoint:     server.URL + "/ocm",
				Capabilities: []string{"http-sig"},
				ResourceTypes: []discovery.ResourceType{
					{
						Name:       "file",
						ShareTypes: []string{"user"},
						Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm")},
					},
				},
			})
		case "/ocm/token":
			tokenEndpointCalled = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(token.TokenResponse{
				AccessToken: "should-not-be-returned",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF: config.SSRFConfig{Mode: "off"},
	}, nil))
	discClient := discovery.NewClient(httpclient.New(&config.OutboundHTTPConfig{
		SSRF:             config.SSRFConfig{Mode: "off"},
		MaxResponseBytes: config.DefaultMaxResponseBytes,
	}, nil), nil)

	client := tokenoutgoing.NewClient(
		httpClient,
		discClient,
		&mockSigner{},
		makePolicy("strict", nil),
		"my-instance.example.com",
	)

	_, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL + "/ocm/token",
		PeerDomain:    "peer.example.com",
		SharedSecret:  "test-secret",
	})
	if err == nil {
		t.Fatal("expected capability-missing failure")
	}

	var ce *reason.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}
	if ce.ReasonCode != reason.ReasonPeerCapabilityMissing {
		t.Fatalf("expected reason %q, got %q", reason.ReasonPeerCapabilityMissing, ce.ReasonCode)
	}
	if tokenEndpointCalled {
		t.Fatal("token endpoint should not be called when peer lacks exchange-token capability")
	}
}

func TestClient_Exchange_RejectsOversizeResponse(t *testing.T) {
	oversizeBody := make([]byte, config.DefaultMaxResponseBytes+1)
	for i := range oversizeBody {
		oversizeBody[i] = 'x'
	}

	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(oversizeBody)
	}))
	defer server.Close()

	_, err := exchangeOnServer(t, server.URL, "test-secret")
	assertTokenInvalidFormat(t, err)
}

func TestClient_Exchange_RejectsNonJSONContentType(t *testing.T) {
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	_, err := exchangeOnServer(t, server.URL, "test-secret")
	assertTokenInvalidFormat(t, err)
}

func TestClient_Exchange_RejectsEmptyAccessToken(t *testing.T) {
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	client := tokenoutgoing.NewClient(
		httpClient,
		dummyDiscClient(),
		&mockSigner{},
		makePolicy("strict", nil),
		"my-instance.example.com",
	)
	return client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: serverURL,
		PeerDomain:    "peer.example.com",
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
