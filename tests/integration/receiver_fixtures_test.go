// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"crypto/tls"
	"encoding/json"
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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
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
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(disc)
		case jwks.WellKnownPath:
			if km == nil {
				http.Error(w, "receiver signing key not initialized", http.StatusServiceUnavailable)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(km.JWKS())
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
			_, _ = w.Write([]byte(`{"recipientDisplayName":"Strict Receiver"}`))
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

func tlsPeerInput(peerURL string) (baseURL, host string) {
	parsed, err := url.Parse(peerURL)
	if err != nil {
		return peerURL, strings.TrimPrefix(strings.TrimPrefix(peerURL, "https://"), "http://")
	}

	return peerURL, parsed.Host
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

	receiver := &strictRecordingReceiver{}

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/ocm":
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
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(disc)
		case r.URL.Path == jwks.WellKnownPath:
			if km == nil {
				http.Error(w, "receiver signing key not initialized", http.StatusServiceUnavailable)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(km.JWKS())
		case r.URL.Path == "/ocm/shares" && r.Method == http.MethodPost:
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

			capture := strictRecordingShareCapture{
				ProviderID:   req.ProviderID,
				SharedSecret: req.Protocol.WebDAV.SharedSecret,
				Requirements: append([]string(nil), req.Protocol.WebDAV.Requirements...),
				SawSignature: r.Header.Get("Signature") != "",
				RawBody:      append([]byte(nil), body...),
			}

			receiver.mu.Lock()
			receiver.lastShare = capture
			receiver.mu.Unlock()
			receiver.postCount.Add(1)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"recipientDisplayName":"Strict Recording Receiver"}`))
		case r.URL.Path == "/ocm/token" && r.Method == http.MethodPost:
			receiver.tokenPostCount.Add(1)

			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid token form", http.StatusBadRequest)
				return
			}

			receiver.mu.Lock()
			receiver.lastTokenForm = copyURLValues(r.PostForm)
			receiver.mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(spec.TokenResponse{
				AccessToken: "recording-receiver-access-token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			})
		case strings.HasPrefix(r.URL.Path, "/webdav/ocm/"):
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}

			if r.Header.Get("Authorization") == "" {
				http.Error(w, "missing authorization", http.StatusUnauthorized)
				return
			}

			receiver.webDAVGetCount.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("strict-recording-webdav-stub"))
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
	server        *http.Server
	peerDomain    string
	peerBaseURL   string
	port          int
	postCount     atomic.Int32
	discoveryHits atomic.Int32
}

func (p *trustedProtocolPeer) Close() {
	if p != nil && p.server != nil {
		_ = p.server.Close()
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

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen trusted protocol peer: %v", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	peer := &trustedProtocolPeer{
		port:        port,
		peerDomain:  fmt.Sprintf("localhost:%d", port),
		peerBaseURL: fmt.Sprintf("https://localhost:%d", port),
	}
	peer.server = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/ocm" {
				peer.discoveryHits.Add(1)
			}

			handler(peer, w, r)
		}),
	}

	go func() {
		_ = peer.server.Serve(tlsListener)
	}()

	t.Cleanup(func() {
		peer.Close()
	})

	return peer
}
