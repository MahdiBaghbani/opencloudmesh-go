package shares_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func outgoingCreateBody(receiverHost, localPath string) string {
	return `{
		"receiverDomain": "` + receiverHost + `",
		"shareWith": "bob@` + receiverHost + `",
		"localPath": "` + localPath + `",
		"permissions": ["read"]
	}`
}

func TestHandleCreate_RejectsReceiverWithoutTokenExchange(t *testing.T) {
	srv, postCount := makeReceiverTLSServer([]string{}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	handler := newStrictOutgoingHandler(t, repo, discClient, ctxClient, user)

	tmpFile := createTempShareFile(t, "outgoing-no-tx-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != reason.APIStatus(reason.PeerCapabilityMismatch) {
		t.Fatalf("expected %d, got %d: %s", reason.APIStatus(reason.PeerCapabilityMismatch), w.Code, w.Body.String())
	}

	if postCount.Load() != 0 {
		t.Fatalf("expected no remote POST, got %d", postCount.Load())
	}
}

func TestHandleCreate_RejectsNilPeerOrigin(t *testing.T) {
	srv, postCount := makeReceiverTLSServer([]string{"exchange-token"}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	handler := newStrictOutgoingHandler(t, repo, discClient, ctxClient, user)
	handler.SetPeerOrigin(nil)

	tmpFile := createTempShareFile(t, "outgoing-nil-peer-origin-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != reason.APIStatus(reason.PeerDiscoveryFailed) {
		t.Fatalf("expected %d, got %d: %s", reason.APIStatus(reason.PeerDiscoveryFailed), w.Code, w.Body.String())
	}

	if postCount.Load() != 0 {
		t.Fatalf("expected no remote POST, got %d", postCount.Load())
	}

	all, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}

	if len(all) != 0 {
		t.Fatalf("expected no stored shares, got %d", len(all))
	}
}

func TestHandleCreate_AbsoluteWebDAVReceiveURI(t *testing.T) {
	srv, postCount, captured := makeCapturingReceiverWithWebDAVReceive(
		[]string{"exchange-token"},
		spec.WebDAVReceiveURIAbsolute,
		"/webdav/ocm/",
	)
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	handler := newStrictOutgoingHandler(t, repo, discClient, ctxClient, user)

	tmpFile := createTempShareFile(t, "outgoing-abs-uri-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if postCount.Load() != 1 {
		t.Fatalf("expected one POST, got %d", postCount.Load())
	}

	if captured.Protocol.WebDAV == nil {
		t.Fatal("expected webdav protocol in captured payload")
	}

	uri := captured.Protocol.WebDAV.URI
	if !strings.HasPrefix(uri, srv.URL) {
		t.Fatalf("expected absolute uri under receiver origin, got %q", uri)
	}

	if !strings.Contains(uri, "/webdav/ocm/") {
		t.Fatalf("expected webdav path in uri, got %q", uri)
	}

	if !captured.Protocol.WebDAV.HasRequirement(spec.RequirementMustExchangeToken) {
		t.Fatal("expected must-exchange-token requirement on wire payload")
	}
}

func TestHandleCreate_RejectsMismatchedAuthorityAbsoluteWebDAVReceiveURI(t *testing.T) {
	srv, postCount := makeCapturingReceiverWithMismatchedEndpoint(
		[]string{"exchange-token"},
		spec.WebDAVReceiveURIAbsolute,
		"/webdav/ocm/",
		"https://evil.example.com/ocm",
	)
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	handler := newStrictOutgoingHandler(t, repo, discClient, ctxClient, user)

	tmpFile := createTempShareFile(t, "outgoing-bad-abs-uri-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != reason.APIStatus(reason.PeerDiscoveryFailed) {
		t.Fatalf("expected %d, got %d: %s", reason.APIStatus(reason.PeerDiscoveryFailed), w.Code, w.Body.String())
	}

	if postCount.Load() != 0 {
		t.Fatalf("expected no remote POST, got %d", postCount.Load())
	}

	all, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}

	if len(all) != 0 {
		t.Fatalf("expected no stored shares, got %d", len(all))
	}
}

func TestHandleCreate_RelativeWebDAVReceiveURIUsesBareUUID(t *testing.T) {
	srv, _, captured := makeCapturingReceiverWithWebDAVReceive(
		[]string{"exchange-token"},
		spec.WebDAVReceiveURIRelative,
		"/webdav/ocm/",
	)
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	handler := newStrictOutgoingHandler(t, repo, discClient, ctxClient, user)

	tmpFile := createTempShareFile(t, "outgoing-rel-uri-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if captured.Protocol.WebDAV == nil {
		t.Fatal("expected webdav protocol in captured payload")
	}

	if strings.Contains(captured.Protocol.WebDAV.URI, "://") {
		t.Fatalf("expected bare uuid uri, got %q", captured.Protocol.WebDAV.URI)
	}

	if !captured.Protocol.WebDAV.HasRequirement(spec.RequirementMustExchangeToken) {
		t.Fatal("expected must-exchange-token requirement on wire payload")
	}
}

func TestHandleCreate_AbsentWebDAVReceiveURIUsesBareUUID(t *testing.T) {
	srv, _, captured := makeCapturingReceiverTLSServer([]string{"exchange-token"}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	handler := newStrictOutgoingHandler(t, repo, discClient, ctxClient, user)

	tmpFile := createTempShareFile(t, "outgoing-no-receive-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if captured.Protocol.WebDAV == nil {
		t.Fatal("expected webdav protocol in captured payload")
	}

	if strings.Contains(captured.Protocol.WebDAV.URI, "://") {
		t.Fatalf("expected bare uuid uri, got %q", captured.Protocol.WebDAV.URI)
	}

	if !captured.Protocol.WebDAV.HasRequirement(spec.RequirementMustExchangeToken) {
		t.Fatal("expected must-exchange-token requirement on wire payload")
	}

	all, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}

	if len(all) != 1 {
		t.Fatalf("expected one stored share, got %d", len(all))
	}
}

func makeCapturingReceiverWithWebDAVReceive(
	capabilities []string,
	receiveKind spec.WebDAVReceiveURIKind,
	webdavRoot string,
) (*httptest.Server, *atomic.Int32, *spec.NewShareRequest) {
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

			protocols := spec.Protocols{
				"webdav": spec.StringProtocolRole(webdavRoot),
			}
			if receiveKind != "" {
				protocols["webdav-receive"] = spec.WebDAVReceiveRole(receiveKind)
			}

			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      srv.URL + "/ocm",
				Capabilities:  capabilities,
				TokenEndPoint: tokenEndPoint,
				ResourceTypes: []spec.ResourceType{{
					Name:       "file",
					ShareTypes: []string{"user"},
					Protocols:  protocols,
				}},
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

func makeCapturingReceiverWithMismatchedEndpoint(
	capabilities []string,
	receiveKind spec.WebDAVReceiveURIKind,
	webdavRoot string,
	endpointURL string,
) (*httptest.Server, *atomic.Int32) {
	postCount := &atomic.Int32{}

	var srv *httptest.Server

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			tokenEndPoint := ""
			if hasExchangeTokenCapability(capabilities) {
				tokenEndPoint = srv.URL + "/ocm/token"
			}

			protocols := spec.Protocols{
				"webdav": spec.StringProtocolRole(webdavRoot),
			}
			if receiveKind != "" {
				protocols["webdav-receive"] = spec.WebDAVReceiveRole(receiveKind)
			}

			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      endpointURL,
				Capabilities:  capabilities,
				TokenEndPoint: tokenEndPoint,
				ResourceTypes: []spec.ResourceType{{
					Name:       "file",
					ShareTypes: []string{"user"},
					Protocols:  protocols,
				}},
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
