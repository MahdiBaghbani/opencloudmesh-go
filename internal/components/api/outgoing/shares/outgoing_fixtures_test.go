package shares_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

const testProvider = "example.com"

func testCurrentUser(user *identity.User) func(context.Context) (*identity.User, error) {
	return func(ctx context.Context) (*identity.User, error) {
		return user, nil
	}
}

func makeDummyDiscoveryClient() *discovery.Client {
	hc := httpclient.New(nil, nil)
	return discovery.NewClient(hc, nil)
}

func makeReceiverTLSServer(capabilities, criteria []string) (*httptest.Server, *atomic.Int32) {
	postCount := &atomic.Int32{}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			tokenEndPoint := ""
			if hasCapability(capabilities, "exchange-token") {
				tokenEndPoint = srv.URL + "/ocm/token"
			}
			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      srv.URL + "/ocm",
				Capabilities:  capabilities,
				Criteria:      criteria,
				TokenEndPoint: tokenEndPoint,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(disc)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/ocm/shares" {
			postCount.Add(1)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	return srv, postCount
}

func makeCapturingReceiverTLSServer(capabilities, criteria []string) (*httptest.Server, *atomic.Int32, *spec.NewShareRequest) {
	postCount := &atomic.Int32{}
	var captured spec.NewShareRequest
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			tokenEndPoint := ""
			if hasCapability(capabilities, "exchange-token") {
				tokenEndPoint = srv.URL + "/ocm/token"
			}
			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      srv.URL + "/ocm",
				Capabilities:  capabilities,
				Criteria:      criteria,
				TokenEndPoint: tokenEndPoint,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(disc)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/ocm/shares" {
			postCount.Add(1)
			_ = json.NewDecoder(r.Body).Decode(&captured)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	return srv, postCount, &captured
}

func makeMalformedCapableReceiverTLSServer(criteria []string) (*httptest.Server, *atomic.Int32) {
	postCount := &atomic.Int32{}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := spec.Discovery{
				Enabled:      true,
				APIVersion:   "1.4.0",
				EndPoint:     srv.URL + "/ocm",
				Capabilities: []string{"exchange-token"},
				Criteria:     criteria,
				// Intentionally omit tokenEndPoint to simulate malformed discovery.
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(disc)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/ocm/shares" {
			postCount.Add(1)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	return srv, postCount
}

// makeCountingReceiverTLSServer counts discovery and shares-POST hits so tests
// can assert the send path does not trigger a second discovery round trip.
func makeCountingReceiverTLSServer(capabilities, criteria []string) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	discoverCount := &atomic.Int32{}
	postCount := &atomic.Int32{}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			discoverCount.Add(1)
			tokenEndPoint := ""
			if hasCapability(capabilities, "exchange-token") {
				tokenEndPoint = srv.URL + "/ocm/token"
			}
			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      srv.URL + "/ocm",
				Capabilities:  capabilities,
				Criteria:      criteria,
				TokenEndPoint: tokenEndPoint,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(disc)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/ocm/shares" {
			postCount.Add(1)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	return srv, discoverCount, postCount
}

func hasCapability(capabilities []string, capability string) bool {
	for _, c := range capabilities {
		if c == capability {
			return true
		}
	}
	return false
}

func makeTLSClients() (*discovery.Client, *httpclient.ContextClient) {
	cfg := tshttp.PermissiveConfig()
	cfg.DerivedSSRFMode = "off"
	cfg.InsecureSkipVerify = true
	raw := httpclient.New(cfg, nil)
	return discovery.NewClient(raw, nil), httpclient.NewContextClient(raw)
}

// makeNoCacheTLSClients wires a discovery client with caching disabled so that
// any discovery call reaches the network, letting tests count discovery hits.
func makeNoCacheTLSClients() (*discovery.Client, *httpclient.ContextClient) {
	cfg := tshttp.PermissiveConfig()
	cfg.DerivedSSRFMode = "off"
	cfg.InsecureSkipVerify = true
	raw := httpclient.New(cfg, nil)
	return discovery.NewClient(raw, cache.NewNoopCache()), httpclient.NewContextClient(raw)
}

func createTempShareFile(t *testing.T, pattern string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("/tmp", pattern)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	path := tmpFile.Name()
	_ = tmpFile.Close()
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

func failCurrentUser() func(context.Context) (*identity.User, error) {
	return func(ctx context.Context) (*identity.User, error) {
		return nil, http.ErrNoCookie
	}
}

func makeTestSigner(t *testing.T) *crypto.RFC9421Signer {
	t.Helper()
	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("failed to generate test signing key: %v", err)
	}
	return crypto.NewRFC9421Signer(km)
}

func makeTestOutboundPolicy(cfg *config.Config) *outboundsigning.OutboundPolicy {
	contract, err := peercompat.NewCompiledContract(nil, nil)
	if err != nil {
		panic(err)
	}
	return outboundsigning.NewOutboundPolicy(outboundsigning.ResolveInputs(), contract)
}

func newTestHandler(currentUser func(context.Context) (*identity.User, error)) *outgoingshares.Handler {
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient := makeDummyDiscoveryClient()

	return outgoingshares.NewHandler(
		repo, discClient, nil, "", nil, nil, nil,
		testProvider,
		currentUser,
		testLogger,
	)
}
