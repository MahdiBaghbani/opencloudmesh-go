// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
)

// TestOutgoingShareResponseRedactsSharedSecret proves the browser-facing response
// from POST /api/shares/outgoing never contains the generated sharedSecret.
// The secret is still forwarded to the remote receiver inside the WebDAV protocol
// payload, but it must not be echoed back to the browser.
func TestOutgoingShareResponseRedactsSharedSecret(t *testing.T) {
	receiver, captured := makeCapturingReceiverTLSServerForRedaction(t, []string{"exchange-token"}, []string{})
	defer receiver.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	handler := newOutgoingHandlerForRedaction(t, user)

	tmpFile := createTempFileForRedaction(t, "ocm-redaction-*")
	payload := map[string]any{
		"receiverDomain": receiver.Listener.Addr().String(),
		"shareWith":      "bob@" + receiver.Listener.Addr().String(),
		"localPath":      tmpFile,
		"permissions":    []string{"read"},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if captured.Protocol.WebDAV == nil || captured.Protocol.WebDAV.SharedSecret == "" {
		t.Fatal("receiver did not receive a WebDAV sharedSecret")
	}

	sharedSecret := captured.Protocol.WebDAV.SharedSecret
	if strings.Contains(w.Body.String(), sharedSecret) {
		t.Fatalf("browser-facing response contains sharedSecret %q: %s", sharedSecret, w.Body.String())
	}

	if strings.Contains(strings.ToLower(w.Body.String()), "sharedsecret") {
		t.Fatalf("browser-facing response contains sharedSecret field: %s", w.Body.String())
	}
}

func makeCapturingReceiverTLSServerForRedaction(t *testing.T, capabilities, criteria []string) (*httptest.Server, *spec.NewShareRequest) {
	t.Helper()

	var (
		captured spec.NewShareRequest
		srv      *httptest.Server
	)

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			tshttp.WriteJSON(w, spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      srv.URL + "/ocm",
				Capabilities:  capabilities,
				Criteria:      criteria,
				TokenEndPoint: srv.URL + "/ocm/token",
			})
		case "/ocm/shares":
			if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
				t.Errorf("decode share request: %v", err)
				w.WriteHeader(http.StatusBadRequest)

				return
			}

			w.WriteHeader(http.StatusCreated)
			tshttp.MustWrite(t, w, []byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))

	return srv, &captured
}

func newOutgoingHandlerForRedaction(t *testing.T, user *identity.User) *outgoingshares.Handler {
	t.Helper()

	cfg := tshttp.PermissiveConfig()
	cfg.InsecureSkipVerify = true
	rawClient := httpclient.New(cfg, nil)
	discClient := discovery.NewClient(rawClient, nil)
	ctxClient := httpclient.NewContextClient(rawClient)

	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	signer := makeTestSignerForRedaction(t)

	resolver := &stubResolverForRedaction{facts: policy.NewCodeFlow().Evaluate()}
	handler := outgoingshares.NewHandler(
		repo,
		discClient,
		ctxClient,
		signer,
		"example.com",
		func(_ context.Context) (*identity.User, error) { return user, nil },
		testLoggerForRedaction(),
		resolver,
		"https://example.com/ocm/token",
	)
	handler.SetAllowedPaths([]string{"/tmp"})
	handler.SetPeerOrigin(peerorigin.NewResolver(false))

	return handler
}

func makeTestSignerForRedaction(t *testing.T) *crypto.RFC9421Signer {
	t.Helper()

	km := crypto.NewKeyManager("", "https://example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("failed to generate test signing key: %v", err)
	}

	return crypto.NewRFC9421Signer(km)
}

func testLoggerForRedaction() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

type stubResolverForRedaction struct {
	facts policy.Facts
}

func (r *stubResolverForRedaction) ResolveFacts(_ string) policy.Facts {
	return r.facts
}

func createTempFileForRedaction(t *testing.T, pattern string) string {
	t.Helper()

	tmpFile, err := os.CreateTemp("/tmp", pattern)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	path := tmpFile.Name()

	if err := tmpFile.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}

	t.Cleanup(func() {
		if err := os.Remove(path); err != nil {
			t.Errorf("remove temp file: %v", err)
		}
	})

	return path
}
