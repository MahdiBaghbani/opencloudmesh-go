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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

func TestClient_Exchange_Success(t *testing.T) {
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("expected form-urlencoded, got %s", r.Header.Get("Content-Type"))
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
		DerivedSSRFMode: "off",
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
	if result.QuirkApplied != "" {
		t.Errorf("expected no quirk applied, got %s", result.QuirkApplied)
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
		DerivedSSRFMode: "off",
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

	var ce *peercompat.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}
	if ce.ReasonCode != peercompat.ReasonDiscoveryFailed {
		t.Fatalf("expected reason %q, got %q", peercompat.ReasonDiscoveryFailed, ce.ReasonCode)
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
		DerivedSSRFMode:  "off",
		MaxResponseBytes: 1 << 20,
	}, nil))
	discClient := discovery.NewClient(httpclient.New(&config.OutboundHTTPConfig{
		DerivedSSRFMode:  "off",
		MaxResponseBytes: 1 << 20,
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

	var ce *peercompat.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}
	if ce.ReasonCode != peercompat.ReasonSignatureRequired {
		t.Fatalf("expected reason %q, got %q (cause=%v err=%v)", peercompat.ReasonSignatureRequired, ce.ReasonCode, ce.Cause, err)
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
		DerivedSSRFMode:  "off",
		MaxResponseBytes: 1 << 20,
	}, nil))
	discClient := discovery.NewClient(httpclient.New(&config.OutboundHTTPConfig{
		DerivedSSRFMode:  "off",
		MaxResponseBytes: 1 << 20,
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

	var ce *peercompat.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}
	if ce.ReasonCode != peercompat.ReasonDiscoveryFailed {
		t.Fatalf("expected reason %q, got %q", peercompat.ReasonDiscoveryFailed, ce.ReasonCode)
	}
	if tokenEndpointCalled {
		t.Fatal("token endpoint should not be called when rediscovery fails")
	}
}

func TestClient_Exchange_AcceptPlainTokenUnsignedRetry(t *testing.T) {
	var tokenHits atomic.Int32
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHits.Add(1)
		if r.Header.Get("Signature") != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(token.OAuthError{
				Error:            token.ErrorUnauthorized,
				ErrorDescription: "signature not accepted",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "plain-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		DerivedSSRFMode: "off",
	}, nil))

	contract, err := peercompat.NewCompiledContract(
		map[string]*peercompat.Profile{
			"compat": {
				Name:                "compat",
				TokenExchangeQuirks: []string{"accept_plain_token"},
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: "peer.example.com", Profile: "compat"},
		},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract: %v", err)
	}
	policy := makePolicy("strict", nil)
	policy.PeerContract = contract

	client := tokenoutgoing.NewClient(
		httpClient,
		dummyDiscClient(),
		&mockSigner{},
		policy,
		"my-instance.example.com",
	)

	result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		PeerDomain:    "peer.example.com",
		SharedSecret:  "test-secret",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if result.AccessToken != "plain-token" {
		t.Fatalf("AccessToken = %q", result.AccessToken)
	}
	if result.QuirkApplied != "accept_plain_token" {
		t.Fatalf("QuirkApplied = %q, want accept_plain_token", result.QuirkApplied)
	}
	if got := tokenHits.Load(); got != 2 {
		t.Fatalf("token endpoint hits = %d, want 2 (signed then unsigned)", got)
	}
}

func TestClient_Exchange_AcceptPlainToken_Bare401AfterSigned(t *testing.T) {
	var tokenHits atomic.Int32
	server := newDiscoveryAwareTokenServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHits.Add(1)
		if r.Header.Get("Signature") != "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(token.TokenResponse{
			AccessToken: "bare-401-plain",
			TokenType:   "Bearer",
			ExpiresIn:   60,
		})
	}))
	defer server.Close()

	httpClient := httpclient.NewContextClient(httpclient.New(&config.OutboundHTTPConfig{
		DerivedSSRFMode: "off",
	}, nil))

	contract, err := peercompat.NewCompiledContract(
		map[string]*peercompat.Profile{
			"compat": {
				Name:                "compat",
				TokenExchangeQuirks: []string{"accept_plain_token"},
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: "peer.example.com", Profile: "compat"},
		},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract: %v", err)
	}
	policy := makePolicy("strict", nil)
	policy.PeerContract = contract

	client := tokenoutgoing.NewClient(
		httpClient,
		dummyDiscClient(),
		&mockSigner{},
		policy,
		"my-instance.example.com",
	)

	result, err := client.Exchange(context.Background(), tokenoutgoing.ExchangeRequest{
		TokenEndPoint: server.URL,
		PeerDomain:    "peer.example.com",
		SharedSecret:  "test-secret",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if result.QuirkApplied != "accept_plain_token" {
		t.Fatalf("QuirkApplied = %q", result.QuirkApplied)
	}
	if tokenHits.Load() != 2 {
		t.Fatalf("hits = %d, want 2", tokenHits.Load())
	}
}

func TestClient_Exchange_AcceptPlainToken_UnmatchedPeerNoDowngrade(t *testing.T) {
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
		DerivedSSRFMode: "off",
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
		t.Fatal("expected failure without accept_plain_token mapping")
	}
	if tokenHits.Load() != 1 {
		t.Fatalf("hits = %d, want 1 (no unsigned retry)", tokenHits.Load())
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
		DerivedSSRFMode: "off",
	}, nil))
	discClient := discovery.NewClient(httpclient.New(&config.OutboundHTTPConfig{
		DerivedSSRFMode:  "off",
		MaxResponseBytes: 1 << 20,
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

	var ce *peercompat.ClassifiedError
	if !isClassifiedError(err, &ce) {
		t.Fatalf("expected ClassifiedError, got %T", err)
	}
	if ce.ReasonCode != peercompat.ReasonPeerCapabilityMissing {
		t.Fatalf("expected reason %q, got %q", peercompat.ReasonPeerCapabilityMissing, ce.ReasonCode)
	}
	if tokenEndpointCalled {
		t.Fatal("token endpoint should not be called when peer lacks exchange-token capability")
	}
}
