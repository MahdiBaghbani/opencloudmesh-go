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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/ocm/configfixture"
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

	var (
		captured spec.NewShareRequest
		srv      *httptest.Server
	)

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
	cfg.InsecureSkipVerify = true
	raw := httpclient.New(cfg, nil)

	return discovery.NewClient(raw, nil), httpclient.NewContextClient(raw)
}

// makeNoCacheTLSClients wires a discovery client with caching disabled so that
// any discovery call reaches the network, letting tests count discovery hits.
func makeNoCacheTLSClients() (*discovery.Client, *httpclient.ContextClient) {
	cfg := tshttp.PermissiveConfig()
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

// stubResolver implements PeerFactsResolver for tests without touching the real
// peer-mapping config surface.
type stubResolver struct {
	facts policy.Facts
}

func (r *stubResolver) ResolveFacts(host string, disc policy.DiscoveryView) policy.Facts {
	return r.facts
}

func newTestHandler(currentUser func(context.Context) (*identity.User, error)) *outgoingshares.Handler {
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient := makeDummyDiscoveryClient()

	return outgoingshares.NewHandler(
		repo,
		discClient,
		nil,
		nil,
		testProvider,
		currentUser,
		testLogger,
		&stubResolver{facts: policy.NewCodeFlow().Evaluate()},
		"https://example.com/ocm/token",
	)
}

func newOutgoingHandler(
	t *testing.T,
	repo sharesoutgoing.OutgoingShareRepo,
	discClient *discovery.Client,
	ctxClient *httpclient.ContextClient,
	user *identity.User,
	resolver outgoingshares.PeerFactsResolver,
	localTokenEndPoint string,
) *outgoingshares.Handler {
	t.Helper()

	if resolver == nil {
		resolver = &stubResolver{facts: policy.NewCodeFlow().Evaluate()}
	}

	if localTokenEndPoint == "" {
		localTokenEndPoint = "https://example.com/ocm/token"
	}

	handler := outgoingshares.NewHandler(
		repo,
		discClient,
		ctxClient,
		makeTestSigner(t),
		testProvider,
		testCurrentUser(user),
		testLogger,
		resolver,
		localTokenEndPoint,
	)
	handler.SetAllowedPaths([]string{"/tmp"})
	handler.SetPeerOrigin(peerorigin.NewResolver(false))

	return handler
}

func newStrictOutgoingHandler(
	t *testing.T,
	repo sharesoutgoing.OutgoingShareRepo,
	discClient *discovery.Client,
	ctxClient *httpclient.ContextClient,
	user *identity.User,
) *outgoingshares.Handler {
	t.Helper()
	return newOutgoingHandler(t, repo, discClient, ctxClient, user, nil, "")
}

func newLegacyVoluntaryOutgoingHandler(
	t *testing.T,
	repo sharesoutgoing.OutgoingShareRepo,
	discClient *discovery.Client,
	ctxClient *httpclient.ContextClient,
	user *identity.User,
) *outgoingshares.Handler {
	t.Helper()

	resolver := &stubResolver{facts: configfixture.CodeFlowLegacyVoluntary().Evaluate()}

	return newOutgoingHandler(t, repo, discClient, ctxClient, user, resolver, "")
}
