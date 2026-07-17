package shares_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

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
		repo, discClient, policy.NewOpenCloudMeshPolicy(cfg), ctxClient, makeTestSigner(t), makeTestOutboundPolicy(cfg),
		testProvider, testCurrentUser(user), testLogger,
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
		repo, discClient, policy.NewOpenCloudMeshPolicy(cfg), ctxClient, makeTestSigner(t), makeTestOutboundPolicy(cfg),
		testProvider, testCurrentUser(user), testLogger,
	)
	handler.SetAllowedPaths([]string{"/tmp"})

	tmpFile, err := os.CreateTemp("/tmp", "outgoing-failfast-plain-*")
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
	srv, postCount := makeMalformedCapableReceiverTLSServer([]string{spec.CriteriaMustExchangeToken})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	cfg := config.DevConfig()
	cfg.PeerPolicy = "strict"
	enabled := true
	cfg.TokenExchange.Enabled = &enabled

	discClient, ctxClient := makeTLSClients()
	handler := outgoingshares.NewHandler(
		repo, discClient, policy.NewOpenCloudMeshPolicy(cfg), ctxClient, makeTestSigner(t), makeTestOutboundPolicy(cfg),
		testProvider, testCurrentUser(user), testLogger,
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
		repo, discClient, policy.NewOpenCloudMeshPolicy(cfg), ctxClient, makeTestSigner(t), makeTestOutboundPolicy(cfg),
		testProvider, testCurrentUser(user), testLogger,
	)
	handler.SetAllowedPaths([]string{"/tmp"})

	filePath := createTempShareFile(t, "outgoing-malformed-plain-*")
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
		repo, discClient, policy.NewOpenCloudMeshPolicy(cfg), ctxClient, makeTestSigner(t), makeTestOutboundPolicy(cfg),
		testProvider, testCurrentUser(user), testLogger,
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

// TestHandleCreate_SendReusesPreflightDiscovery proves the send path reuses the
// discovery already fetched during the compatibility preflight instead of
// discovering again. Caching is disabled so a second discovery would hit the
// server; with reuse the receiver sees exactly one discovery and one POST.
func TestHandleCreate_SendReusesPreflightDiscovery(t *testing.T) {
	srv, discoverCount, postCount := makeCountingReceiverTLSServer([]string{"exchange-token"}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	cfg := config.DevConfig()
	cfg.PeerPolicy = "legacy"
	enabled := true
	cfg.TokenExchange.Enabled = &enabled
	discClient, ctxClient := makeNoCacheTLSClients()
	handler := outgoingshares.NewHandler(
		repo, discClient, policy.NewOpenCloudMeshPolicy(cfg), ctxClient, makeTestSigner(t), makeTestOutboundPolicy(cfg),
		testProvider, testCurrentUser(user), testLogger,
	)
	handler.SetAllowedPaths([]string{"/tmp"})

	filePath := createTempShareFile(t, "outgoing-reuse-discovery-*")
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
	if got := discoverCount.Load(); got != 1 {
		t.Fatalf("expected exactly one discovery (preflight only), got %d", got)
	}
	if got := postCount.Load(); got != 1 {
		t.Fatalf("expected exactly one shares POST, got %d", got)
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
				repo, discClient, policy.NewOpenCloudMeshPolicy(cfg), ctxClient, makeTestSigner(t), makeTestOutboundPolicy(cfg),
				testProvider, testCurrentUser(user), testLogger,
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

func TestHandleCreate_CanonicalStrictPeerRequiresExchangeWhenCodeFlowEnabled(t *testing.T) {
	srv, postCount, captured := makeCapturingReceiverTLSServer(
		[]string{"exchange-token"},
		[]string{spec.CriteriaMustExchangeToken},
	)
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	cfg := config.DevConfig()
	cfg.PeerPolicy = "legacy"
	enabled := true
	cfg.TokenExchange.Enabled = &enabled

	discClient, ctxClient := makeTLSClients()
	handler := outgoingshares.NewHandler(
		repo, discClient, policy.NewOpenCloudMeshPolicy(cfg), ctxClient, makeTestSigner(t), makeTestOutboundPolicy(cfg),
		testProvider, testCurrentUser(user), testLogger,
	)
	handler.SetAllowedPaths([]string{"/tmp"})

	filePath := createTempShareFile(t, "outgoing-canonical-strict-enabled-*")
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
		t.Fatalf("expected one remote POST, got %d", postCount.Load())
	}
	if captured.Protocol.Name != "webdav" {
		t.Fatalf("expected protocol.name webdav, got %q", captured.Protocol.Name)
	}
	if captured.Protocol.WebDAV == nil || !captured.Protocol.WebDAV.HasRequirement(spec.RequirementMustExchangeToken) {
		t.Fatal("expected outgoing share to require must-exchange-token for canonical strict peer")
	}
	all, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("failed to list shares: %v", err)
	}
	if len(all) != 1 || !all[0].MustExchangeToken {
		t.Fatalf("expected stored MustExchangeToken=true, got %+v", all)
	}
}

func TestHandleCreate_CanonicalStrictPeerRejectsWithoutCodeFlow(t *testing.T) {
	srv, postCount := makeReceiverTLSServer(
		[]string{"exchange-token"},
		[]string{spec.CriteriaMustExchangeToken},
	)
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	cfg := config.DevConfig()
	cfg.PeerPolicy = "legacy"
	enabled := false
	cfg.TokenExchange.Enabled = &enabled

	discClient, ctxClient := makeTLSClients()
	handler := outgoingshares.NewHandler(
		repo, discClient, policy.NewOpenCloudMeshPolicy(cfg), ctxClient, makeTestSigner(t), makeTestOutboundPolicy(cfg),
		testProvider, testCurrentUser(user), testLogger,
	)
	handler.SetAllowedPaths([]string{"/tmp"})

	filePath := createTempShareFile(t, "outgoing-canonical-strict-disabled-*")
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

	if w.Code != reason.APIStatus(reason.PeerCapabilityMismatch) {
		t.Fatalf("expected %d, got %d: %s", reason.APIStatus(reason.PeerCapabilityMismatch), w.Code, w.Body.String())
	}
	if postCount.Load() != 0 {
		t.Fatalf("expected no remote POST attempt, got %d", postCount.Load())
	}
}

func TestHandleCreate_EmitsWebDAVProtocolName(t *testing.T) {
	srv, postCount, captured := makeCapturingReceiverTLSServer([]string{"exchange-token"}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	cfg := config.DevConfig()
	cfg.PeerPolicy = "legacy"
	enabled := true
	cfg.TokenExchange.Enabled = &enabled
	discClient, ctxClient := makeTLSClients()
	handler := outgoingshares.NewHandler(
		repo, discClient, policy.NewOpenCloudMeshPolicy(cfg), ctxClient, makeTestSigner(t), makeTestOutboundPolicy(cfg),
		testProvider, testCurrentUser(user), testLogger,
	)
	handler.SetAllowedPaths([]string{"/tmp"})

	filePath := createTempShareFile(t, "outgoing-proto-name-*")
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
		t.Fatalf("expected one remote POST, got %d", postCount.Load())
	}
	if captured.Protocol.Name != "webdav" {
		t.Fatalf("expected protocol.name webdav, got %q", captured.Protocol.Name)
	}
}
