// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/ocm/configfixture"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

const testProvider = "example.com"

func testCurrentUser(user *identity.User) func(context.Context) (*identity.User, error) {
	return func(_ context.Context) (*identity.User, error) {
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
			if hasExchangeTokenCapability(capabilities) {
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
			_ = json.NewEncoder(w).Encode(disc) //nolint:errcheck // test mock handler: JSON encode

			return
		}

		if r.Method == http.MethodPost && r.URL.Path == "/ocm/shares" {
			postCount.Add(1)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ok":true}`)) //nolint:errcheck // test mock handler: response write

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
			if hasExchangeTokenCapability(capabilities) {
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
			_ = json.NewEncoder(w).Encode(disc) //nolint:errcheck // test mock handler: JSON encode

			return
		}

		if r.Method == http.MethodPost && r.URL.Path == "/ocm/shares" {
			postCount.Add(1)

			_ = json.NewDecoder(r.Body).Decode(&captured) //nolint:errcheck // test mock handler: JSON decode

			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ok":true}`)) //nolint:errcheck // test mock handler: response write

			return
		}

		http.NotFound(w, r)
	}))

	return srv, postCount, &captured
}

func hasExchangeTokenCapability(capabilities []string) bool {
	for _, c := range capabilities {
		if c == "exchange-token" {
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

func createTempShareFile(t *testing.T, pattern string) string {
	t.Helper()

	tmpFile, err := os.CreateTemp("/tmp", pattern)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	path := tmpFile.Name()
	_ = tmpFile.Close() //nolint:errcheck // test cleanup: resource close

	t.Cleanup(func() { _ = os.Remove(path) }) //nolint:errcheck // test cleanup: temp path removal

	return path
}

func failCurrentUser() func(context.Context) (*identity.User, error) {
	return func(_ context.Context) (*identity.User, error) {
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

func (r *stubResolver) ResolveFacts(_ string) policy.Facts {
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
