package discovery_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestClientDiscover_RejectsNonAbsoluteEndPoint(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, nil)
		raw["endPoint"] = "/ocm"

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)

	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for non-absolute endPoint")
	}

	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

func TestClientDiscover_RejectsCrossAuthorityEndPoint(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, nil)
		raw["endPoint"] = "https://other.example.com/ocm"

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)

	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for cross-authority endPoint")
	}

	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

func TestClientDiscover_RejectsExchangeTokenWithoutTokenEndPoint(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"capabilities": []string{"exchange-token"},
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)

	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for exchange-token without tokenEndPoint")
	}

	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

func TestClientDiscover_RejectsTokenEndPointWithoutExchangeTokenCapability(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"tokenEndPoint": strings.TrimSuffix(serverURL, "/") + "/token",
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)

	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for tokenEndPoint without exchange-token capability")
	}

	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

func TestClientDiscover_RejectsNonAbsoluteTokenEndPoint(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"capabilities":  []string{"exchange-token"},
			"tokenEndPoint": "/token",
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)

	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for non-absolute tokenEndPoint")
	}

	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

func TestClientDiscover_RejectsCrossAuthorityTokenEndPoint(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, map[string]any{
			"capabilities":  []string{"exchange-token"},
			"tokenEndPoint": "https://other.example.com/token",
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)

	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for cross-authority tokenEndPoint")
	}

	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}
