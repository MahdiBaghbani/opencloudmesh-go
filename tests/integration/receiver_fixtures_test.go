// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package integration

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

type strictCodeFlowShareCapture struct {
	ProviderID   string
	SharedSecret string
	Requirements []string
	SawSignature bool
}

type strictCodeFlowReceiver struct {
	server      *httptest.Server
	peerDomain  string
	peerBaseURL string
	signer      *crypto.RFC9421Signer
	captures    chan strictCodeFlowShareCapture
}

func startStrictCodeFlowReceiver(t *testing.T) *strictCodeFlowReceiver {
	t.Helper()

	captures := make(chan strictCodeFlowShareCapture, 1)

	var (
		srv *httptest.Server
		km  *crypto.KeyManager
	)

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			if km == nil {
				http.Error(w, "receiver signing key not initialized", http.StatusServiceUnavailable)
				return
			}

			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      srv.URL + "/ocm",
				ResourceTypes: []spec.ResourceType{{Name: "file", ShareTypes: []string{"user"}, Protocols: spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm/")}}},
				Capabilities:  []string{"exchange-token", "http-sig"},
				Criteria:      []string{spec.CriteriaMustExchangeToken, spec.CriteriaMustUseHTTPSig},
				TokenEndPoint: srv.URL + "/ocm/token",
				JwksUri:       srv.URL + "/ocm/jwks",
			}

			w.Header().Set("Content-Type", "application/json")
			tshttp.WriteJSON(w, disc)
		case "/ocm/jwks":
			if km == nil {
				http.Error(w, "receiver signing key not initialized", http.StatusServiceUnavailable)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			tshttp.WriteJSON(w, km.JWKS())
		case "/ocm/shares":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read share body", http.StatusBadRequest)
				return
			}

			var req spec.NewShareRequest
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, "failed to parse share body", http.StatusBadRequest)
				return
			}

			if req.Protocol.WebDAV == nil {
				http.Error(w, "missing webdav payload", http.StatusBadRequest)
				return
			}

			capture := strictCodeFlowShareCapture{
				ProviderID:   req.ProviderID,
				SharedSecret: req.Protocol.WebDAV.SharedSecret,
				Requirements: append([]string(nil), req.Protocol.WebDAV.Requirements...),
				SawSignature: r.Header.Get("Signature") != "",
			}
			select {
			case captures <- capture:
			default:
				<-captures

				captures <- capture
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			tshttp.MustWrite(t, w, []byte(`{"recipientDisplayName":"Strict Receiver"}`))
		default:
			http.NotFound(w, r)
		}
	}))

	km = crypto.NewKeyManager("", srv.URL)
	if err := km.LoadOrGenerate(); err != nil {
		srv.Close()
		t.Fatalf("failed to create strict receiver signing key: %v", err)
	}

	km.SetWireKeyID(srv.URL + "#key1")

	parsedURL, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatalf("failed to parse strict receiver URL: %v", err)
	}

	return &strictCodeFlowReceiver{
		server:      srv,
		peerDomain:  parsedURL.Host,
		peerBaseURL: srv.URL,
		signer:      crypto.NewRFC9421Signer(km),
		captures:    captures,
	}
}

func (r *strictCodeFlowReceiver) Close() {
	if r != nil && r.server != nil {
		r.server.Close()
	}
}

func (r *strictCodeFlowReceiver) waitForShare(t *testing.T) strictCodeFlowShareCapture {
	t.Helper()

	select {
	case capture := <-r.captures:
		return capture
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for strict share capture")
		return strictCodeFlowShareCapture{}
	}
}

// strictRecordingShareCapture records one inbound /ocm/shares POST.
type strictRecordingShareCapture struct {
	ProviderID   string
	SharedSecret string
	Requirements []string
	SawSignature bool
	RawBody      []byte
}

// strictRecordingReceiver is a strict-capable httptest peer that records share
// and token exchange traffic and exposes a minimal WebDAV stub.
type strictRecordingReceiver struct {
	t              *testing.T
	server         *httptest.Server
	peerDomain     string
	peerBaseURL    string
	postCount      atomic.Int32
	tokenPostCount atomic.Int32
	webDAVGetCount atomic.Int32

	mu            sync.Mutex
	lastShare     strictRecordingShareCapture
	lastTokenForm url.Values
}

func startStrictRecordingReceiver(t *testing.T) *strictRecordingReceiver {
	t.Helper()

	var (
		srv *httptest.Server
		km  *crypto.KeyManager
	)

	receiver := &strictRecordingReceiver{t: t}

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/ocm":
			serveRecordingDiscovery(w, srv, km)
		case r.URL.Path == "/ocm/jwks":
			serveRecordingJWKS(w, km)
		case r.URL.Path == "/ocm/shares" && r.Method == http.MethodPost:
			receiver.serveRecordingShare(w, r)
		case r.URL.Path == "/ocm/token" && r.Method == http.MethodPost:
			receiver.serveRecordingToken(w, r)
		case strings.HasPrefix(r.URL.Path, "/webdav/ocm/"):
			receiver.serveRecordingWebDAV(w, r)
		default:
			http.NotFound(w, r)
		}
	}))

	km = crypto.NewKeyManager("", srv.URL)
	if err := km.LoadOrGenerate(); err != nil {
		srv.Close()
		t.Fatalf("failed to create strict recording receiver signing key: %v", err)
	}

	km.SetWireKeyID(srv.URL + "#key1")

	parsedURL, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatalf("failed to parse strict recording receiver URL: %v", err)
	}

	receiver.server = srv
	receiver.peerDomain = parsedURL.Host
	receiver.peerBaseURL = srv.URL

	return receiver
}

// serveRecordingDiscovery serves the strict discovery document for the receiver.
func serveRecordingDiscovery(w http.ResponseWriter, srv *httptest.Server, km *crypto.KeyManager) {
	if km == nil {
		http.Error(w, "receiver signing key not initialized", http.StatusServiceUnavailable)
		return
	}

	disc := spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      srv.URL + "/ocm",
		ResourceTypes: []spec.ResourceType{{Name: "file", ShareTypes: []string{"user"}, Protocols: spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm/")}}},
		Capabilities:  []string{"exchange-token", "http-sig"},
		Criteria:      []string{spec.CriteriaMustExchangeToken, spec.CriteriaMustUseHTTPSig},
		TokenEndPoint: srv.URL + "/ocm/token",
		JwksUri:       srv.URL + "/ocm/jwks",
	}

	w.Header().Set("Content-Type", "application/json")
	tshttp.WriteJSON(w, disc)
}

// serveRecordingJWKS serves the receiver JWKS.
func serveRecordingJWKS(w http.ResponseWriter, km *crypto.KeyManager) {
	if km == nil {
		http.Error(w, "receiver signing key not initialized", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	tshttp.WriteJSON(w, km.JWKS())
}

// serveRecordingShare records an inbound share POST and returns 201.
func (r *strictRecordingReceiver) serveRecordingShare(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "failed to read share body", http.StatusBadRequest)
		return
	}

	var shareReq spec.NewShareRequest
	if err := json.Unmarshal(body, &shareReq); err != nil {
		http.Error(w, "failed to parse share body", http.StatusBadRequest)
		return
	}

	if shareReq.Protocol.WebDAV == nil {
		http.Error(w, "missing webdav payload", http.StatusBadRequest)
		return
	}

	capture := strictRecordingShareCapture{
		ProviderID:   shareReq.ProviderID,
		SharedSecret: shareReq.Protocol.WebDAV.SharedSecret,
		Requirements: append([]string(nil), shareReq.Protocol.WebDAV.Requirements...),
		SawSignature: req.Header.Get("Signature") != "",
		RawBody:      append([]byte(nil), body...),
	}

	r.mu.Lock()
	r.lastShare = capture
	r.mu.Unlock()
	r.postCount.Add(1)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	tshttp.MustWrite(r.t, w, []byte(`{"recipientDisplayName":"Strict Recording Receiver"}`))
}

// serveRecordingToken records a token exchange POST and returns a token.
func (r *strictRecordingReceiver) serveRecordingToken(w http.ResponseWriter, req *http.Request) {
	r.tokenPostCount.Add(1)

	if err := req.ParseForm(); err != nil {
		http.Error(w, "invalid token form", http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	r.lastTokenForm = copyURLValues(req.PostForm)
	r.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	tshttp.WriteJSON(w, spec.TokenResponse{
		AccessToken: "recording-receiver-access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	})
}

// serveRecordingWebDAV serves the minimal WebDAV stub.
func (r *strictRecordingReceiver) serveRecordingWebDAV(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if req.Header.Get("Authorization") == "" {
		http.Error(w, "missing authorization", http.StatusUnauthorized)
		return
	}

	r.webDAVGetCount.Add(1)
	w.WriteHeader(http.StatusOK)
	tshttp.MustWrite(r.t, w, []byte("strict-recording-webdav-stub"))
}

func copyURLValues(src url.Values) url.Values {
	if src == nil {
		return nil
	}

	dst := make(url.Values, len(src))
	for k, vs := range src {
		dst[k] = append([]string(nil), vs...)
	}

	return dst
}

func (r *strictRecordingReceiver) Close() {
	if r != nil && r.server != nil {
		r.server.Close()
	}
}

func (r *strictRecordingReceiver) PostCount() int32 {
	return r.postCount.Load()
}

func (r *strictRecordingReceiver) TokenPostCount() int32 {
	return r.tokenPostCount.Load()
}

func (r *strictRecordingReceiver) WebDAVGetCount() int32 {
	return r.webDAVGetCount.Load()
}

func assertRecordingReceiverIdle(t *testing.T, receiver *strictRecordingReceiver) {
	t.Helper()

	if receiver == nil {
		t.Fatal("strict recording receiver is nil")
	}

	if n := receiver.PostCount(); n > 0 {
		t.Fatalf("expected recording receiver postCount=0, got %d", n)
	}

	if n := receiver.TokenPostCount(); n > 0 {
		t.Fatalf("expected recording receiver tokenPostCount=0, got %d", n)
	}

	if n := receiver.WebDAVGetCount(); n > 0 {
		t.Fatalf("expected recording receiver webDAVGetCount=0, got %d", n)
	}
}

func (r *strictRecordingReceiver) LastShare() strictRecordingShareCapture {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.lastShare
}

func (r *strictRecordingReceiver) LastTokenForm() url.Values {
	r.mu.Lock()
	defer r.mu.Unlock()

	return copyURLValues(r.lastTokenForm)
}

func strictRecordingReceiverAllowedPort(t *testing.T, receiver *strictRecordingReceiver) int {
	t.Helper()

	if receiver == nil {
		t.Fatal("strict recording receiver is nil")
	}

	_, portStr, err := net.SplitHostPort(receiver.peerDomain)
	if err != nil {
		t.Fatalf("parse strict recording receiver peer domain %q: %v", receiver.peerDomain, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse strict recording receiver port %q: %v", portStr, err)
	}

	return port
}

// trustedProtocolPeer serves HTTPS using the shared dockypody-signed localhost
// fixture certificate so strict subprocess servers trust it via tls_root_ca_file.
type trustedProtocolPeer struct {
	t             *testing.T
	server        *http.Server
	peerDomain    string
	peerBaseURL   string
	port          int
	postCount     atomic.Int32
	discoveryHits atomic.Int32
}

func (p *trustedProtocolPeer) Close() {
	if p != nil && p.server != nil {
		if err := p.server.Close(); err != nil && p.t != nil {
			p.t.Errorf("close trusted protocol peer: %v", err)
		}
	}
}

func (p *trustedProtocolPeer) Port() int {
	if p == nil {
		return 0
	}

	return p.port
}

func (p *trustedProtocolPeer) PostCount() int32 {
	if p == nil {
		return 0
	}

	return p.postCount.Load()
}

func (p *trustedProtocolPeer) DiscoveryHits() int32 {
	if p == nil {
		return 0
	}

	return p.discoveryHits.Load()
}

func startTrustedProtocolPeer(t *testing.T, handler func(peer *trustedProtocolPeer, w http.ResponseWriter, r *http.Request)) *trustedProtocolPeer {
	t.Helper()

	moduleRoot := modroot.ModuleRoot(t)
	certFile := filepath.Join(moduleRoot, "tests", "e2e", "testdata", "tls", "localhost.crt")
	keyFile := filepath.Join(moduleRoot, "tests", "e2e", "testdata", "tls", "localhost.key")

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load trusted protocol peer TLS key pair: %v", err)
	}

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen trusted protocol peer: %v", err)
	}

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("trusted protocol peer listener address type = %T, want *net.TCPAddr", listener.Addr())
	}

	port := tcpAddr.Port
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	peer := &trustedProtocolPeer{
		t:           t,
		port:        port,
		peerDomain:  fmt.Sprintf("localhost:%d", port),
		peerBaseURL: fmt.Sprintf("https://localhost:%d", port),
	}
	peer.server = &http.Server{ //nolint:gosec // test server: short-lived, no Slowloris risk
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/ocm" {
				peer.discoveryHits.Add(1)
			}

			handler(peer, w, r)
		}),
	}

	go func() {
		if err := peer.server.Serve(tlsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("trusted protocol peer serve: %v", err)
		}
	}()

	t.Cleanup(func() {
		peer.Close()
	})

	return peer
}
