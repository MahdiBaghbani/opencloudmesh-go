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

func TestClientDiscover_AcceptsLowerAPIVersionWithWarning(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, nil)
		raw["apiVersion"] = "1.2.2"

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)

	disc, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if len(disc.Warnings) == 0 {
		t.Fatal("expected apiVersion warning in disc.Warnings")
	}

	found := false

	for _, w := range disc.Warnings {
		if strings.Contains(w, "differs from pin") {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("expected differs-from-pin warning, got %v", disc.Warnings)
	}
}

func TestClientDiscover_RejectsAPIVersionUnderExactPolicy(t *testing.T) {
	server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		raw := validDiscoveryPayload(serverURL, nil)
		raw["apiVersion"] = "1.2.2"

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
	})

	client := discovery.NewClient(httpclient.New(tshttp.PermissiveConfig(), nil), nil)
	client.SetVersionPolicy(&discovery.VersionPolicy{
		Mode: discovery.APIVersionExact,
		Warn: discovery.WarnNone,
	})

	_, err := client.Discover(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for non-pin apiVersion under exact policy")
	}

	if !errors.Is(err, discovery.ErrInvalidDiscoveryJSON) {
		t.Fatalf("errors.Is(err, ErrInvalidDiscoveryJSON) = false, err = %v", err)
	}
}

func TestClientDiscover_VersionPolicyModes(t *testing.T) {
	httpCfg := tshttp.PermissiveConfig()

	t.Run("exact rejects 1.3.0", func(t *testing.T) {
		server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, nil)
			raw["apiVersion"] = "1.3.0"
			json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
		})
		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
		client.SetVersionPolicy(&discovery.VersionPolicy{
			Mode: discovery.APIVersionExact,
			Warn: discovery.WarnNone,
		})

		_, err := client.Discover(context.Background(), server.URL)
		if err == nil {
			t.Fatal("expected rejection under exact policy")
		}
	})

	t.Run("at-least-1.4 accepts 1.4.0 and 2.0.0 rejects 1.3.0", func(t *testing.T) {
		policy := &discovery.VersionPolicy{
			Mode: discovery.APIVersionAtLeast14,
			Warn: discovery.WarnNone,
		}

		for _, v := range []string{"1.4.0", "2.0.0"} {
			t.Run("accept_"+v, func(t *testing.T) {
				server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
					raw := validDiscoveryPayload(serverURL, nil)
					raw["apiVersion"] = v
					json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
				})
				client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
				client.SetVersionPolicy(policy)

				if _, err := client.Discover(context.Background(), server.URL); err != nil {
					t.Fatalf("Discover(%s) failed: %v", v, err)
				}
			})
		}

		server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, nil)
			raw["apiVersion"] = "1.3.0"
			json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
		})
		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
		client.SetVersionPolicy(policy)

		if _, err := client.Discover(context.Background(), server.URL); err == nil {
			t.Fatal("expected rejection for 1.3.0 under at-least-1.4")
		}
	})

	t.Run("accept-any accepts all non-empty", func(t *testing.T) {
		for _, v := range []string{"1.1.0", "1.3.0", "2.0.0"} {
			t.Run(v, func(t *testing.T) {
				server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
					raw := validDiscoveryPayload(serverURL, nil)
					raw["apiVersion"] = v
					json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
				})

				client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
				if _, err := client.Discover(context.Background(), server.URL); err != nil {
					t.Fatalf("Discover(%s) failed: %v", v, err)
				}
			})
		}
	})
}

func TestClientDiscover_WarnModesUnderAcceptAny(t *testing.T) {
	httpCfg := tshttp.PermissiveConfig()

	t.Run("any-diff warns on 1.3.0 and 2.0.0", func(t *testing.T) {
		policy := &discovery.VersionPolicy{Mode: discovery.APIVersionAcceptAny, Warn: discovery.WarnAnyDiff}

		for _, v := range []string{"1.3.0", "2.0.0"} {
			t.Run(v, func(t *testing.T) {
				server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
					raw := validDiscoveryPayload(serverURL, nil)
					raw["apiVersion"] = v
					json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
				})
				client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
				client.SetVersionPolicy(policy)

				disc, err := client.Discover(context.Background(), server.URL)
				if err != nil {
					t.Fatalf("Discover failed: %v", err)
				}

				if !hasDiffersFromPinWarning(disc.Warnings) {
					t.Fatalf("expected differs-from-pin warning for %s, got %v", v, disc.Warnings)
				}
			})
		}
	})

	t.Run("lower-only warns on 1.3.0 not 2.0.0", func(t *testing.T) {
		policy := &discovery.VersionPolicy{Mode: discovery.APIVersionAcceptAny, Warn: discovery.WarnLowerOnly}
		serverLow := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, nil)
			raw["apiVersion"] = "1.3.0"
			json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
		})
		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
		client.SetVersionPolicy(policy)

		disc, err := client.Discover(context.Background(), serverLow.URL)
		if err != nil {
			t.Fatalf("Discover failed: %v", err)
		}

		if len(disc.Warnings) == 0 {
			t.Fatal("expected lower-only warning for 1.3.0")
		}

		serverHigh := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, nil)
			raw["apiVersion"] = "2.0.0"
			json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
		})
		client2 := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
		client2.SetVersionPolicy(policy)

		disc2, err := client2.Discover(context.Background(), serverHigh.URL)
		if err != nil {
			t.Fatalf("Discover failed: %v", err)
		}

		for _, w := range disc2.Warnings {
			if strings.Contains(w, "lower than pin") {
				t.Fatalf("unexpected lower warning for 2.0.0: %v", disc2.Warnings)
			}
		}
	})

	t.Run("none never warns", func(t *testing.T) {
		policy := &discovery.VersionPolicy{Mode: discovery.APIVersionAcceptAny, Warn: discovery.WarnNone}
		server := newDiscoveryTestServer(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
			raw := validDiscoveryPayload(serverURL, nil)
			raw["apiVersion"] = "1.3.0"
			json.NewEncoder(w).Encode(raw) //nolint:errcheck // test mock handler: JSON encode
		})
		client := discovery.NewClient(httpclient.New(httpCfg, nil), nil)
		client.SetVersionPolicy(policy)

		disc, err := client.Discover(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("Discover failed: %v", err)
		}

		if len(disc.Warnings) != 0 {
			t.Fatalf("expected no warnings, got %v", disc.Warnings)
		}
	})
}
