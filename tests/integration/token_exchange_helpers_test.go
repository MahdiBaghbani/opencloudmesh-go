// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/tests/integration/harness"
)

func startMalformedCapableNonStrictReceiver(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()

	postCount := &atomic.Int32{}
	mustExchangeFlag := &atomic.Int32{}
	mustExchangeFlag.Store(-1)
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm", "/ocm-provider":
			disc := spec.Discovery{
				Enabled:      true,
				APIVersion:   "1.2.2",
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
	ProviderID        string
	SharedSecret      string
	MustExchangeToken bool
	SawSignature      bool
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
		case "/.well-known/ocm", "/ocm-provider":
			if km == nil {
				http.Error(w, "receiver signing key not initialized", http.StatusServiceUnavailable)
				return
			}
			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.2.2",
				EndPoint:      srv.URL + "/ocm",
				ResourceTypes: []spec.ResourceType{{Name: "file", ShareTypes: []string{"user"}, Protocols: map[string]string{"webdav": "/webdav/ocm/"}}},
				Capabilities:  []string{"exchange-token", "http-sig"},
				Criteria:      []string{"token-exchange", "http-request-signatures"},
				PublicKeys: []spec.PublicKey{{
					KeyID:        km.GetKeyID(),
					PublicKeyPem: km.GetPublicKeyPEM(),
					Algorithm:    "ed25519",
				}},
				TokenEndPoint: srv.URL + "/ocm/token",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(disc)
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
				ProviderID:        req.ProviderID,
				SharedSecret:      req.Protocol.WebDAV.SharedSecret,
				MustExchangeToken: req.Protocol.WebDAV.HasRequirement(spec.RequirementMustExchangeToken),
				SawSignature:      r.Header.Get("Signature") != "",
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

func loginSubprocessAdmin(t *testing.T, srv *harness.SubprocessServer) string {
	t.Helper()

	if token, _, ok := tryLogin(t, srv.BaseURL, "admin", "admin"); ok {
		return token
	}

	logPath := filepath.Join(srv.TempDir, "server.log")
	logs, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read subprocess log for bootstrap password: %v", err)
	}

	password := extractBootstrapPassword(string(logs))
	if password == "" {
		t.Fatalf("could not find bootstrap admin password in server log:\n%s", logs)
	}

	token, body, ok := tryLogin(t, srv.BaseURL, "admin", password)
	if !ok {
		t.Fatalf("login failed with logged bootstrap password %q: %s", password, body)
	}
	return token
}

func tryLogin(t *testing.T, baseURL, username, password string) (string, string, bool) {
	t.Helper()

	reqBody, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		t.Fatalf("failed to encode login request: %v", err)
	}
	resp, err := http.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to call login endpoint: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", string(body), false
	}

	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("failed to parse login response: %v", err)
	}
	if parsed.Token == "" {
		return "", string(body), false
	}
	return parsed.Token, string(body), true
}

func extractBootstrapPassword(logs string) string {
	marker := `"password":"`
	start := strings.Index(logs, marker)
	if start == -1 {
		return ""
	}
	start += len(marker)
	end := strings.Index(logs[start:], `"`)
	if end == -1 {
		return ""
	}
	return logs[start : start+end]
}

func loginAdmin(t *testing.T, baseURL, username, password string) string {
	t.Helper()

	reqBody, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		t.Fatalf("failed to encode login request: %v", err)
	}
	resp, err := http.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("failed to call login endpoint: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: status=%d body=%s", resp.StatusCode, body)
	}

	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("failed to parse login response: %v", err)
	}
	if parsed.Token == "" {
		t.Fatalf("login returned empty token: %s", body)
	}
	return parsed.Token
}

func createOutgoingShare(t *testing.T, baseURL, token string, payload map[string]any) (int, string) {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal outgoing share payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/shares/outgoing", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create outgoing share request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to call outgoing share endpoint: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(respBody)
}
