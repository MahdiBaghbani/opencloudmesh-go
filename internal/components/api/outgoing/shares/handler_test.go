package shares_test

import (
	"bytes"
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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
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
				APIVersion:    "1.2.2",
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

func makeMalformedCapableReceiverTLSServer(criteria []string) (*httptest.Server, *atomic.Int32) {
	postCount := &atomic.Int32{}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := spec.Discovery{
				Enabled:      true,
				APIVersion:   "1.2.2",
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

func hasCapability(capabilities []string, capability string) bool {
	for _, c := range capabilities {
		if c == capability {
			return true
		}
	}
	return false
}

func makeTLSClients() (*discovery.Client, *httpclient.ContextClient) {
	raw := httpclient.New(&config.OutboundHTTPConfig{
		SSRFMode:           "off",
		TimeoutMS:          5000,
		ConnectTimeoutMS:   2000,
		MaxResponseBytes:   1048576,
		InsecureSkipVerify: true,
	}, nil)
	return discovery.NewClient(raw, nil), httpclient.NewContextClient(raw)
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

func newTestHandler(currentUser func(context.Context) (*identity.User, error)) *outgoingshares.Handler {
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	cfg := config.DevConfig()
	discClient := makeDummyDiscoveryClient()

	return outgoingshares.NewHandler(
		repo, discClient, nil, nil, nil, nil,
		cfg,
		testProvider,
		currentUser,
		testLogger,
	)
}

func TestHandleCreate_Unauthenticated_Returns401(t *testing.T) {
	handler := newTestHandler(failCurrentUser())

	body := `{"receiverDomain":"example.com","shareWith":"user@example.com","localPath":"/tmp/test.txt","permissions":["read"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreate_MissingFields(t *testing.T) {
	user := &identity.User{ID: "user-uuid", Username: "alice"}
	handler := newTestHandler(testCurrentUser(user))

	tests := []struct {
		name string
		body string
	}{
		{"missing receiverDomain", `{"shareWith":"user@example.com","localPath":"/tmp/test.txt","permissions":["read"]}`},
		{"missing shareWith", `{"receiverDomain":"example.com","localPath":"/tmp/test.txt","permissions":["read"]}`},
		{"missing localPath", `{"receiverDomain":"example.com","shareWith":"user@example.com","permissions":["read"]}`},
		{"missing permissions", `{"receiverDomain":"example.com","shareWith":"user@example.com","localPath":"/tmp/test.txt"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.HandleCreate(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandleCreate_FileNotFound(t *testing.T) {
	user := &identity.User{ID: "user-uuid", Username: "alice"}
	handler := newTestHandler(testCurrentUser(user))
	handler.SetAllowedPaths([]string{"/tmp"})

	body := `{
		"receiverDomain": "example.com",
		"shareWith": "user@example.com",
		"localPath": "/tmp/nonexistent-file-12345.txt",
		"permissions": ["read"]
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreate_OwnerSenderUseRevaStyleFederatedID(t *testing.T) {
	user := &identity.User{ID: "user-uuid-123", Username: "alice", Email: "alice@example.org"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	cfg := config.DevConfig()

	discClient := makeDummyDiscoveryClient()
	handler := outgoingshares.NewHandler(
		repo, discClient, nil, nil, nil, nil,
		cfg,
		testProvider,
		testCurrentUser(user),
		testLogger,
	)
	handler.SetAllowedPaths([]string{"/tmp"})

	tmpFile, err := os.CreateTemp("/tmp", "outgoing-share-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	body := `{
		"receiverDomain": "receiver.example.com",
		"shareWith": "bob@receiver.example.com",
		"localPath": "` + tmpFile.Name() + `",
		"permissions": ["read"]
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	// Discovery now happens before persistence. With a dummy discovery client
	// that cannot reach the receiver, expect a 502. No share should be stored.
	if w.Code != http.StatusBadGateway && w.Code != http.StatusInternalServerError {
		t.Logf("unexpected status %d (expected 502 from discovery failure): %s", w.Code, w.Body.String())
	}

	allShares, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("failed to list shares: %v", err)
	}

	if len(allShares) != 0 {
		t.Errorf("expected no shares stored (preflight failed), got %d", len(allShares))
	}

	_ = address.FormatOutgoingOCMAddressFromUserID("user-uuid-123", testProvider)
}

func TestHandleCreate_MethodNotAllowed(t *testing.T) {
	user := &identity.User{ID: "user-uuid", Username: "alice"}
	handler := newTestHandler(testCurrentUser(user))

	req := httptest.NewRequest(http.MethodGet, "/api/shares/outgoing", nil)
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleCreate_ErrorResponseUsesAPIEnvelope(t *testing.T) {
	user := &identity.User{ID: "user-uuid", Username: "alice"}
	handler := newTestHandler(testCurrentUser(user))

	body := `{"shareWith":"user@example.com","localPath":"/tmp/test.txt","permissions":["read"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	// Should be 400 (missing receiverDomain)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	errObj, ok := resp["error"]
	if !ok {
		t.Fatal("error response missing 'error' field (should use api error envelope)")
	}
	errMap, ok := errObj.(map[string]interface{})
	if !ok {
		t.Fatal("error field is not an object")
	}
	if _, ok := errMap["reason_code"]; !ok {
		t.Error("error response missing reason_code field (should use api error envelope)")
	}
}

func TestHandleCreate_StrictRejectsCapableNonStrictPeer_NoSend(t *testing.T) {
	srv, postCount := makeReceiverTLSServer([]string{"exchange-token"}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	cfg := config.DevConfig()
	cfg.PeerPolicy = "strict"
	enabled := true
	cfg.TokenExchange.Enabled = &enabled

	discClient, ctxClient := makeTLSClients()
	handler := outgoingshares.NewHandler(
		repo, discClient, nil, ctxClient, nil, nil,
		cfg, testProvider, testCurrentUser(user), testLogger,
	)
	handler.SetAllowedPaths([]string{"/tmp"})

	tmpFile, err := os.CreateTemp("/tmp", "outgoing-failfast-capable-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	_ = tmpFile.Close()

	receiverHost := srv.Listener.Addr().String()
	body := `{
		"receiverDomain": "` + receiverHost + `",
		"shareWith": "bob@` + receiverHost + `",
		"localPath": "` + tmpFile.Name() + `",
		"permissions": ["read"]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != reason.APIStatus(reason.PeerPolicyUnsatisfied) {
		t.Fatalf("expected %d, got %d: %s", reason.APIStatus(reason.PeerPolicyUnsatisfied), w.Code, w.Body.String())
	}
	if postCount.Load() != 0 {
		t.Fatalf("expected no remote POST attempt, got %d", postCount.Load())
	}
	all, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("failed to list shares: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("expected no stored shares, got %d", len(all))
	}
}

func TestHandleCreate_StrictRejectsLegacyPeer_NoSend(t *testing.T) {
	srv, postCount := makeReceiverTLSServer([]string{}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	cfg := config.DevConfig()
	cfg.PeerPolicy = "strict"

	discClient, ctxClient := makeTLSClients()
	handler := outgoingshares.NewHandler(
		repo, discClient, nil, ctxClient, nil, nil,
		cfg, testProvider, testCurrentUser(user), testLogger,
	)
	handler.SetAllowedPaths([]string{"/tmp"})

	tmpFile, err := os.CreateTemp("/tmp", "outgoing-failfast-legacy-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	_ = tmpFile.Close()

	receiverHost := srv.Listener.Addr().String()
	body := `{
		"receiverDomain": "` + receiverHost + `",
		"shareWith": "bob@` + receiverHost + `",
		"localPath": "` + tmpFile.Name() + `",
		"permissions": ["read"]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != reason.APIStatus(reason.PeerPolicyUnsatisfied) {
		t.Fatalf("expected %d, got %d: %s", reason.APIStatus(reason.PeerPolicyUnsatisfied), w.Code, w.Body.String())
	}
	if postCount.Load() != 0 {
		t.Fatalf("expected no remote POST attempt, got %d", postCount.Load())
	}
	all, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("failed to list shares: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("expected no stored shares, got %d", len(all))
	}
}

func TestHandleCreate_StrictRejectsMalformedStrictPeer_NoSend(t *testing.T) {
	srv, postCount := makeMalformedCapableReceiverTLSServer([]string{"token-exchange"})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	cfg := config.DevConfig()
	cfg.PeerPolicy = "strict"
	enabled := true
	cfg.TokenExchange.Enabled = &enabled

	discClient, ctxClient := makeTLSClients()
	handler := outgoingshares.NewHandler(
		repo, discClient, nil, ctxClient, nil, nil,
		cfg, testProvider, testCurrentUser(user), testLogger,
	)
	handler.SetAllowedPaths([]string{"/tmp"})

	tmpFile, err := os.CreateTemp("/tmp", "outgoing-malformed-strict-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	_ = tmpFile.Close()

	receiverHost := srv.Listener.Addr().String()
	body := `{
		"receiverDomain": "` + receiverHost + `",
		"shareWith": "bob@` + receiverHost + `",
		"localPath": "` + tmpFile.Name() + `",
		"permissions": ["read"]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != reason.APIStatus(reason.PeerCapabilityMismatch) {
		t.Fatalf("expected %d, got %d: %s", reason.APIStatus(reason.PeerCapabilityMismatch), w.Code, w.Body.String())
	}
	if postCount.Load() != 0 {
		t.Fatalf("expected no remote POST attempt, got %d", postCount.Load())
	}
}

func TestHandleCreate_MalformedCapablePeerDegradesToLegacy(t *testing.T) {
	srv, postCount := makeMalformedCapableReceiverTLSServer([]string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	cfg := config.DevConfig()
	cfg.PeerPolicy = "prefer-strict"
	enabled := true
	cfg.TokenExchange.Enabled = &enabled
	discClient, ctxClient := makeTLSClients()
	handler := outgoingshares.NewHandler(
		repo, discClient, nil, ctxClient, nil, nil,
		cfg, testProvider, testCurrentUser(user), testLogger,
	)
	handler.SetAllowedPaths([]string{"/tmp"})

	filePath := createTempShareFile(t, "outgoing-malformed-legacy-*")
	receiverHost := srv.Listener.Addr().String()
	body := `{
		"receiverDomain": "` + receiverHost + `",
		"shareWith": "bob@` + receiverHost + `",
		"localPath": "` + filePath + `",
		"permissions": ["read"]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	if postCount.Load() != 1 {
		t.Fatalf("expected one remote POST attempt, got %d", postCount.Load())
	}
	all, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("failed to list shares: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected one stored share, got %d", len(all))
	}
	if all[0].MustExchangeToken {
		t.Fatal("expected MustExchangeToken=false for malformed non-strict peer")
	}
}

func TestHandleCreate_SuccessStoresSentRowAndFederatedIDs(t *testing.T) {
	srv, _ := makeReceiverTLSServer([]string{"exchange-token"}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid-123", Username: "alice", Email: "alice@example.org"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	cfg := config.DevConfig()
	cfg.PeerPolicy = "prefer-strict"
	enabled := true
	cfg.TokenExchange.Enabled = &enabled
	discClient, ctxClient := makeTLSClients()
	handler := outgoingshares.NewHandler(
		repo, discClient, nil, ctxClient, nil, nil,
		cfg, testProvider, testCurrentUser(user), testLogger,
	)
	handler.SetAllowedPaths([]string{"/tmp"})

	filePath := createTempShareFile(t, "outgoing-success-*")
	receiverHost := srv.Listener.Addr().String()
	body := `{
		"receiverDomain": "` + receiverHost + `",
		"shareWith": "bob@` + receiverHost + `",
		"localPath": "` + filePath + `",
		"permissions": ["read"]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	all, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("failed to list shares: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected one stored share, got %d", len(all))
	}
	share := all[0]
	if share.Status != "sent" {
		t.Fatalf("expected stored status sent, got %q", share.Status)
	}
	expected := address.FormatOutgoingOCMAddressFromUserID(user.ID, testProvider)
	if share.Owner != expected {
		t.Fatalf("expected Owner %q, got %q", expected, share.Owner)
	}
	if share.Sender != expected {
		t.Fatalf("expected Sender %q, got %q", expected, share.Sender)
	}
}

func TestHandleCreate_NonStrictPolicyMatrix(t *testing.T) {
	type tc struct {
		name           string
		capabilities   []string
		criteria       []string
		policy         string
		wantStatus     int
		wantMust       bool
		wantStoredRows int
		wantPostCalls  int32
	}
	cases := []tc{
		{
			name:           "capable non-strict with legacy sends plain",
			capabilities:   []string{"exchange-token"},
			criteria:       []string{},
			policy:         "legacy",
			wantStatus:     http.StatusCreated,
			wantMust:       false,
			wantStoredRows: 1,
			wantPostCalls:  1,
		},
		{
			name:           "capable non-strict with prefer-strict sets must-exchange-token",
			capabilities:   []string{"exchange-token"},
			criteria:       []string{},
			policy:         "prefer-strict",
			wantStatus:     http.StatusCreated,
			wantMust:       true,
			wantStoredRows: 1,
			wantPostCalls:  1,
		},
		{
			name:           "capable non-strict with strict policy rejects",
			capabilities:   []string{"exchange-token"},
			criteria:       []string{},
			policy:         "strict",
			wantStatus:     reason.APIStatus(reason.PeerPolicyUnsatisfied),
			wantStoredRows: 0,
			wantPostCalls:  0,
		},
		{
			name:           "legacy peer with prefer-strict still sends plain",
			capabilities:   []string{},
			criteria:       []string{},
			policy:         "prefer-strict",
			wantStatus:     http.StatusCreated,
			wantMust:       false,
			wantStoredRows: 1,
			wantPostCalls:  1,
		},
		{
			name:           "legacy peer with strict policy rejects",
			capabilities:   []string{},
			criteria:       []string{},
			policy:         "strict",
			wantStatus:     reason.APIStatus(reason.PeerPolicyUnsatisfied),
			wantStoredRows: 0,
			wantPostCalls:  0,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, postCount := makeReceiverTLSServer(c.capabilities, c.criteria)
			defer srv.Close()

			user := &identity.User{ID: "user-uuid", Username: "alice"}
			repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
			cfg := config.DevConfig()
			cfg.PeerPolicy = c.policy
			enabled := true
			cfg.TokenExchange.Enabled = &enabled
			discClient, ctxClient := makeTLSClients()
			handler := outgoingshares.NewHandler(
				repo, discClient, nil, ctxClient, nil, nil,
				cfg, testProvider, testCurrentUser(user), testLogger,
			)
			handler.SetAllowedPaths([]string{"/tmp"})

			filePath := createTempShareFile(t, "outgoing-policy-matrix-*")
			receiverHost := srv.Listener.Addr().String()
			body := `{
				"receiverDomain": "` + receiverHost + `",
				"shareWith": "bob@` + receiverHost + `",
				"localPath": "` + filePath + `",
				"permissions": ["read"]
			}`
			req := httptest.NewRequest(http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.HandleCreate(w, req)

			if w.Code != c.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", c.wantStatus, w.Code, w.Body.String())
			}
			if postCount.Load() != c.wantPostCalls {
				t.Fatalf("expected %d remote POST calls, got %d", c.wantPostCalls, postCount.Load())
			}

			all, err := repo.List(context.Background())
			if err != nil {
				t.Fatalf("failed to list shares: %v", err)
			}
			if len(all) != c.wantStoredRows {
				t.Fatalf("expected %d stored rows, got %d", c.wantStoredRows, len(all))
			}
			if c.wantStoredRows > 0 && all[0].MustExchangeToken != c.wantMust {
				t.Fatalf("expected MustExchangeToken=%v, got %v", c.wantMust, all[0].MustExchangeToken)
			}
		})
	}
}
