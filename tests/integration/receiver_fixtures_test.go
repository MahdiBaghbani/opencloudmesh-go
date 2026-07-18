// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
)

func startMalformedCapableNonStrictReceiver(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()

	postCount := &atomic.Int32{}
	mustExchangeFlag := &atomic.Int32{}
	mustExchangeFlag.Store(-1)
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			disc := spec.Discovery{
				Enabled:      true,
				APIVersion:   "1.4.0",
				EndPoint:     srv.URL + "/ocm",
				Capabilities: []string{"exchange-token"},
				Criteria:     []string{},
				// Intentionally malformed: missing tokenEndPoint.
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(disc)
			return
		case "/ocm/shares":
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			var req spec.NewShareRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid payload", http.StatusBadRequest)
				return
			}
			postCount.Add(1)
			mustExchange := req.Protocol.WebDAV != nil &&
				req.Protocol.WebDAV.HasRequirement(spec.RequirementMustExchangeToken)
			if mustExchange {
				mustExchangeFlag.Store(1)
			} else {
				mustExchangeFlag.Store(0)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		default:
			http.NotFound(w, r)
		}
	}))

	return srv, postCount, mustExchangeFlag
}

type strictCodeFlowShareCapture struct {
	ProviderID   string
	SharedSecret string
	Requirements []string
	SawSignature bool
}

type strictCodeFlowReceiver struct {
	server     *httptest.Server
	peerDomain string
	signer     *crypto.RFC9421Signer
	captures   chan strictCodeFlowShareCapture
}

func startStrictCodeFlowReceiver(t *testing.T) *strictCodeFlowReceiver {
	t.Helper()

	captures := make(chan strictCodeFlowShareCapture, 1)
	var srv *httptest.Server
	var km *crypto.KeyManager
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

	parsedURL, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatalf("failed to parse strict receiver URL: %v", err)
	}

	return &strictCodeFlowReceiver{
		server:     srv,
		peerDomain: parsedURL.Host,
		signer:     crypto.NewRFC9421Signer(km),
		captures:   captures,
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
