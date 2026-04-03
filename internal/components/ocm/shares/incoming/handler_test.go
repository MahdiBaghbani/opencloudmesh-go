package incoming_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

func setupTestPartyRepo() identity.PartyRepo {
	repo := identity.NewMemoryPartyRepo()
	ctx := context.Background()
	repo.Create(ctx, &identity.User{
		ID:          "user-a-uuid",
		Username:    "alice",
		Email:       "alice@example.org",
		DisplayName: "Alice A",
	})
	repo.Create(ctx, &identity.User{
		ID:          "user-b-uuid",
		Username:    "bob",
		Email:       "bob@example.org",
		DisplayName: "Bob B",
	})
	return repo
}

func runtimePolicyForMode(mode string) *policy.RuntimePolicy {
	cfg := config.DevConfig()
	cfg.Signature.InboundMode = mode
	return policy.NewRuntimePolicy(cfg, nil)
}

// newTestHandler creates a handler wired for testing against localhost:9200 (https).
func newTestHandler(repo *sharesinbox.MemoryIncomingShareRepo, partyRepo identity.PartyRepo) *incoming.Handler {
	return incoming.NewHandler(
		repo,
		partyRepo,
		nil, // no policy engine
		nil, // no discovery client
		nil, // no canonical policy
		runtimePolicyForMode("strict"),
		"localhost:9200",
		"https",
		testLogger(),
	)
}

func validShareBody(shareWith string) string {
	return `{
		"shareWith": "` + shareWith + `",
		"name": "test.txt",
		"providerId": "abc123",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "webdav",
			"webdav": {
				"uri": "abc123",
				"sharedSecret": "secret123",
				"permissions": ["read"]
			}
		}
	}`
}

func TestValidateRequiredFields_AllMissing(t *testing.T) {
	req := &spec.NewShareRequest{}
	errs := spec.ValidateRequiredFields(req)

	if len(errs) == 0 {
		t.Fatal("expected validation errors for empty request")
	}

	names := map[string]bool{}
	for _, e := range errs {
		names[e.Name] = true
		if e.Message != "REQUIRED" {
			t.Errorf("expected message REQUIRED for field %s, got %s", e.Name, e.Message)
		}
	}

	required := []string{"shareWith", "name", "providerId", "owner", "sender", "shareType", "resourceType", "protocol"}
	for _, f := range required {
		if !names[f] {
			t.Errorf("expected validation error for field %s", f)
		}
	}
}

func TestValidateRequiredFields_AllPresent(t *testing.T) {
	req := &spec.NewShareRequest{
		ShareWith:    "user@host",
		Name:         "file.txt",
		ProviderID:   "p1",
		Owner:        "o@h",
		Sender:       "s@h",
		ShareType:    "user",
		ResourceType: "file",
		Protocol:     spec.Protocol{Name: "webdav", WebDAV: &spec.WebDAVProtocol{URI: "x"}},
	}
	errs := spec.ValidateRequiredFields(req)
	if len(errs) != 0 {
		t.Errorf("expected no validation errors, got %d", len(errs))
	}
}

func TestValidateRequiredFields_ProtocolWithOnlyWebDAV(t *testing.T) {
	// Protocol has WebDAV but no name -- should not trigger "protocol REQUIRED"
	req := &spec.NewShareRequest{
		ShareWith:    "user@host",
		Name:         "file.txt",
		ProviderID:   "p1",
		Owner:        "o@h",
		Sender:       "s@h",
		ShareType:    "user",
		ResourceType: "file",
		Protocol:     spec.Protocol{WebDAV: &spec.WebDAVProtocol{URI: "x"}},
	}
	errs := spec.ValidateRequiredFields(req)
	if len(errs) != 0 {
		t.Errorf("expected no validation errors for protocol with webdav, got %d: %v", len(errs), errs)
	}
}

func TestCreateShare_Success_ResolvesById(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	// shareWith uses user ID as identifier
	body := validShareBody("user-a-uuid@localhost:9200")

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.CreateShareResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.RecipientDisplayName != "Alice A" {
		t.Errorf("expected recipientDisplayName 'Alice A', got %q", resp.RecipientDisplayName)
	}
}

func TestCreateShare_Success_ResolvesByUsername(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := validShareBody("alice@localhost:9200")
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.CreateShareResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.RecipientDisplayName != "Alice A" {
		t.Errorf("expected recipientDisplayName 'Alice A', got %q", resp.RecipientDisplayName)
	}
}

func TestCreateShare_Success_ResolvesByEmail(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	// Email contains @, so shareWith uses last-@ semantics
	body := validShareBody("alice@example.org@localhost:9200")
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_MissingRequiredFields(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{"name": "test.txt"}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp spec.OCMErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Message != "MISSING_REQUIRED_FIELDS" {
		t.Errorf("expected message MISSING_REQUIRED_FIELDS, got %q", resp.Message)
	}
	if len(resp.ValidationErrors) == 0 {
		t.Error("expected validation errors in response")
	}
}

func TestCreateShare_InvalidOwnerFormat(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "p1",
		"owner": "invalid-no-at",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"]}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid owner, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Message != "INVALID_FIELD_FORMAT" {
		t.Errorf("expected INVALID_FIELD_FORMAT, got %q", resp.Message)
	}

	found := false
	for _, e := range resp.ValidationErrors {
		if e.Name == "owner" && e.Message == "INVALID_FORMAT" {
			found = true
		}
	}
	if !found {
		t.Error("expected validation error for owner with INVALID_FORMAT")
	}
}

func TestCreateShare_ProviderMismatch(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := validShareBody("alice@wrong-provider.com")
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for provider mismatch, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Message != "PROVIDER_MISMATCH" {
		t.Errorf("expected PROVIDER_MISMATCH, got %q", resp.Message)
	}
}

func TestCreateShare_UnsupportedShareType_Returns501(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "p1",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "group",
		"resourceType": "file",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"]}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for unsupported shareType, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Message != "SHARE_TYPE_NOT_SUPPORTED" {
		t.Errorf("expected SHARE_TYPE_NOT_SUPPORTED, got %q", resp.Message)
	}
}

func TestCreateShare_RecipientNotFound(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := validShareBody("nonexistent@localhost:9200")
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown recipient (spec-mandated, not 404), got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Message != "RECIPIENT_NOT_FOUND" {
		t.Errorf("expected RECIPIENT_NOT_FOUND, got %q", resp.Message)
	}

	found := false
	for _, e := range resp.ValidationErrors {
		if e.Name == "shareWith" && e.Message == "NOT_FOUND" {
			found = true
		}
	}
	if !found {
		t.Error("expected validationError {shareWith, NOT_FOUND}")
	}
}

func TestCreateShare_DuplicateReturns200(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := validShareBody("alice@localhost:9200")

	// First request: 201
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("first request: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Second request with same providerId + sender: 200 (idempotent)
	req2 := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handler.CreateShare(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("duplicate request: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var resp spec.CreateShareResponse
	json.NewDecoder(w2.Body).Decode(&resp)
	if resp.RecipientDisplayName != "Alice A" {
		t.Errorf("duplicate response: expected recipientDisplayName 'Alice A', got %q", resp.RecipientDisplayName)
	}
}

func TestCreateShare_AcceptsAllResourceTypes(t *testing.T) {
	// F7=A: accept all resourceType values, do not reject unknown types
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "rt-test",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "calendar",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"]}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for custom resourceType, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateShare_NoWebDAV_Returns501(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "p1",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "webapp"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for missing webdav, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExtractSenderHost(t *testing.T) {
	tests := []struct {
		name     string
		sender   string
		expected string
	}{
		{"simple address", "user@example.com", "example.com"},
		{"with port", "user@example.com:9200", "example.com:9200"},
		{"uppercase host", "user@EXAMPLE.COM", "example.com"},
		{"no @ separator", "invalid", ""},
		{"empty string", "", ""},
		{"email identifier (last-@)", "alice@university.edu@provider.net", "provider.net"},
		{"email identifier with port (last-@)", "alice@uni.edu@provider.net:443", "provider.net:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := incoming.ExtractSenderHost(tt.sender)
			if result != tt.expected {
				t.Errorf("ExtractSenderHost(%q) = %q, want %q", tt.sender, result, tt.expected)
			}
		})
	}
}

func TestCreateShare_Success_ResolvesByFederatedOpaqueID(t *testing.T) {
	// Reva-style federated opaque ID: base64url_padded(userID@localProvider)
	// The encoded identifier won't match any user by raw ID, username, or email,
	// so triple resolution fails and the decode fallback fires.
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	encoded := base64.URLEncoding.EncodeToString([]byte("user-a-uuid@localhost:9200"))
	body := validShareBody(encoded + "@localhost:9200")

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for federated opaque ID, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.CreateShareResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.RecipientDisplayName != "Alice A" {
		t.Errorf("expected recipientDisplayName 'Alice A', got %q", resp.RecipientDisplayName)
	}
}

func TestCreateShare_FederatedOpaqueID_IDPMismatch_Rejected(t *testing.T) {
	// Encoded identifier decodes to a valid userID@idp payload, but the
	// decoded idp doesn't match local provider -- must be rejected.
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	encoded := base64.URLEncoding.EncodeToString([]byte("user-a-uuid@wrong-provider.com"))
	body := validShareBody(encoded + "@localhost:9200")

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for idp mismatch in decoded federated ID, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Message != "RECIPIENT_NOT_FOUND" {
		t.Errorf("expected RECIPIENT_NOT_FOUND, got %q", resp.Message)
	}
}

func TestCreateShare_Base64LikeButNoFederatedPayload_Rejected(t *testing.T) {
	// "YWJj" is base64 of "abc" -- passes charset check but decoded payload
	// has no '@', so DecodeFederatedOpaqueID returns false. Falls through to
	// "recipient not found" since "YWJj" is not a real user.
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := validShareBody("YWJj@localhost:9200")

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for base64-like non-federated identifier, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Message != "RECIPIENT_NOT_FOUND" {
		t.Errorf("expected RECIPIENT_NOT_FOUND, got %q", resp.Message)
	}
}

// fakeDiscoveryServer returns an httptest.Server that serves an OCM discovery
// document at /.well-known/ocm. The caller controls capabilities and criteria
// to exercise the handler's receiver-side classification logic.
func fakeDiscoveryServer(capabilities, criteria []string) *httptest.Server {
	tokenEndPoint := ""
	for _, capability := range capabilities {
		if capability == "exchange-token" {
			tokenEndPoint = "http://placeholder/ocm/token"
			break
		}
	}
	return fakeDiscoveryServerWithTokenEndPoint(capabilities, criteria, tokenEndPoint)
}

func fakeDiscoveryServerWithTokenEndPoint(capabilities, criteria []string, tokenEndPoint string) *httptest.Server {
	disc := spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.2.2",
		EndPoint:      "http://placeholder/ocm",
		Capabilities:  capabilities,
		Criteria:      criteria,
		TokenEndPoint: tokenEndPoint,
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(disc)
	}))
}

// newHandlerWithDiscovery creates a handler that uses a real discovery.Client
// pointed at a fake server. The owner address in the share body must use
// fakeSrv's host so discovery routes to the fake server.
func newHandlerWithDiscovery(
	repo *sharesinbox.MemoryIncomingShareRepo,
	partyRepo identity.PartyRepo,
	fakeSrv *httptest.Server,
	canonicalPolicy *policy.OpenCloudMeshPolicy,
) *incoming.Handler {
	rawHTTP := httpclient.New(&config.OutboundHTTPConfig{
		SSRFMode:           "off",
		TimeoutMS:          5000,
		ConnectTimeoutMS:   2000,
		MaxResponseBytes:   1048576,
		InsecureSkipVerify: true,
	}, nil)
	discClient := discovery.NewClient(rawHTTP, nil)
	return incoming.NewHandler(
		repo,
		partyRepo,
		nil, // no policy engine
		discClient,
		canonicalPolicy,
		runtimePolicyForMode("strict"),
		"localhost:9200",
		"http", // use http so discovery URLs match the httptest server
		testLogger(),
	)
}

// shareBodyWithOwnerHost builds a share JSON where owner (and sender) host
// to ownerHost, and the wire-level must-exchange-token requirement is optionally set.
func shareBodyWithOwnerHost(ownerHost string, mustExchange bool) string {
	return shareBodyWithOwnerAndSenderHosts(ownerHost, ownerHost, mustExchange)
}

func shareBodyWithOwnerAndSenderHosts(ownerHost, senderHost string, mustExchange bool) string {
	requirements := `[]`
	if mustExchange {
		requirements = `["must-exchange-token"]`
	}
	return `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "cls-test",
		"owner": "owner@` + ownerHost + `",
		"sender": "sender@` + senderHost + `",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "webdav",
			"webdav": {
				"uri": "abc123",
				"sharedSecret": "secret123",
				"permissions": ["read"],
				"requirements": ` + requirements + `
			}
		}
	}`
}

// stripSchemeHost returns the host:port from an httptest.Server URL.
func stripSchemeHost(rawURL string) string {
	// "http://127.0.0.1:PORT" -> "127.0.0.1:PORT"
	if len(rawURL) > 7 && rawURL[:7] == "http://" {
		return rawURL[7:]
	}
	return rawURL
}

// TestReceiverClassification_StrictOwner verifies that when the owner's discovery
// document includes "token-exchange" in criteria, owner strictness alone does not
// force must-exchange-token. Local receiver policy owns strictness.
func TestReceiverClassification_StrictOwner(t *testing.T) {
	fakeSrv := fakeDiscoveryServer(
		[]string{"exchange-token"},
		[]string{"token-exchange"},
	)
	defer fakeSrv.Close()

	ownerHost := stripSchemeHost(fakeSrv.URL)

	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newHandlerWithDiscovery(repo, partyRepo, fakeSrv, nil)

	// Wire does NOT set must-exchange-token; this remains opportunistic.
	body := shareBodyWithOwnerHost(ownerHost, false)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	shares, _ := repo.ListByRecipientUserID(context.Background(), "user-a-uuid")
	if len(shares) != 1 {
		t.Fatalf("expected 1 share, got %d", len(shares))
	}
	if shares[0].MustExchangeToken {
		t.Error("strict owner alone: expected MustExchangeToken=false")
	}
	if !shares[0].SenderExchangeCapable {
		t.Error("strict owner: expected SenderExchangeCapable=true")
	}
}

// TestReceiverClassification_CapableOwnerWithWireRequirement verifies that when
// the owner supports exchange-token (not strict) and the wire sets
// must-exchange-token, the share is stored with MustExchangeToken=true.
func TestReceiverClassification_CapableOwnerWithWireRequirement(t *testing.T) {
	fakeSrv := fakeDiscoveryServer(
		[]string{"exchange-token"},
		[]string{}, // not strict
	)
	defer fakeSrv.Close()

	ownerHost := stripSchemeHost(fakeSrv.URL)

	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newHandlerWithDiscovery(repo, partyRepo, fakeSrv, nil)

	body := shareBodyWithOwnerHost(ownerHost, true)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	shares, _ := repo.ListByRecipientUserID(context.Background(), "user-a-uuid")
	if len(shares) != 1 {
		t.Fatalf("expected 1 share, got %d", len(shares))
	}
	if !shares[0].MustExchangeToken {
		t.Error("capable owner + wire requirement: expected MustExchangeToken=true")
	}
	if !shares[0].SenderExchangeCapable {
		t.Error("capable owner + wire requirement: expected SenderExchangeCapable=true")
	}
}

// TestReceiverClassification_CapableOwnerOpportunistic verifies that when the
// owner supports exchange-token but the wire does NOT set must-exchange-token,
// the share is stored with MustExchangeToken=false and SenderExchangeCapable=true.
func TestReceiverClassification_CapableOwnerOpportunistic(t *testing.T) {
	fakeSrv := fakeDiscoveryServer(
		[]string{"exchange-token"},
		[]string{},
	)
	defer fakeSrv.Close()

	ownerHost := stripSchemeHost(fakeSrv.URL)

	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newHandlerWithDiscovery(repo, partyRepo, fakeSrv, nil)

	body := shareBodyWithOwnerHost(ownerHost, false)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	shares, _ := repo.ListByRecipientUserID(context.Background(), "user-a-uuid")
	if len(shares) != 1 {
		t.Fatalf("expected 1 share, got %d", len(shares))
	}
	if shares[0].MustExchangeToken {
		t.Error("capable owner, opportunistic: expected MustExchangeToken=false")
	}
	if !shares[0].SenderExchangeCapable {
		t.Error("capable owner, opportunistic: expected SenderExchangeCapable=true")
	}
}

func TestReceiverClassification_CapabilityWithoutTokenEndpoint_IsNotCapable(t *testing.T) {
	fakeSrv := fakeDiscoveryServerWithTokenEndPoint(
		[]string{"exchange-token"},
		[]string{},
		"",
	)
	defer fakeSrv.Close()

	ownerHost := stripSchemeHost(fakeSrv.URL)

	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newHandlerWithDiscovery(repo, partyRepo, fakeSrv, nil)

	body := shareBodyWithOwnerHost(ownerHost, false)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	shares, _ := repo.ListByRecipientUserID(context.Background(), "user-a-uuid")
	if len(shares) != 1 {
		t.Fatalf("expected 1 share, got %d", len(shares))
	}
	if shares[0].MustExchangeToken {
		t.Error("malformed capability: expected MustExchangeToken=false")
	}
	if shares[0].SenderExchangeCapable {
		t.Error("malformed capability: expected SenderExchangeCapable=false")
	}
}

func TestReceiverClassification_CapabilityWithoutTokenEndpoint_WithMustExchangeRejected(t *testing.T) {
	fakeSrv := fakeDiscoveryServerWithTokenEndPoint(
		[]string{"exchange-token"},
		[]string{},
		"",
	)
	defer fakeSrv.Close()

	ownerHost := stripSchemeHost(fakeSrv.URL)

	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newHandlerWithDiscovery(repo, partyRepo, fakeSrv, nil)

	body := shareBodyWithOwnerHost(ownerHost, true)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code == http.StatusCreated {
		t.Fatalf("expected rejection for malformed exchange-token capability, got %d", w.Code)
	}
}

func TestReceiverClassification_OwnerSenderSplitUsesOwnerForClassifying(t *testing.T) {
	fakeSrv := fakeDiscoveryServer(
		[]string{"exchange-token"},
		[]string{},
	)
	defer fakeSrv.Close()

	ownerHost := stripSchemeHost(fakeSrv.URL)
	senderHost := "relay.example.com"

	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newHandlerWithDiscovery(repo, partyRepo, fakeSrv, nil)

	body := shareBodyWithOwnerAndSenderHosts(ownerHost, senderHost, false)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	shares, _ := repo.ListByRecipientUserID(context.Background(), "user-a-uuid")
	if len(shares) != 1 {
		t.Fatalf("expected 1 share, got %d", len(shares))
	}
	share := shares[0]
	if share.OwnerHost != ownerHost {
		t.Fatalf("expected OwnerHost %q, got %q", ownerHost, share.OwnerHost)
	}
	if share.SenderHost != senderHost {
		t.Fatalf("expected SenderHost %q, got %q", senderHost, share.SenderHost)
	}
	if !share.SenderExchangeCapable {
		t.Fatal("expected SenderExchangeCapable=true from owner-host discovery")
	}
}

// TestReceiverClassification_LegacyOwner verifies contradictory strict claims
// are rejected when the owner lacks exchange-token capability.
func TestReceiverClassification_LegacyOwner(t *testing.T) {
	fakeSrv := fakeDiscoveryServer(
		[]string{}, // no exchange-token
		[]string{},
	)
	defer fakeSrv.Close()

	ownerHost := stripSchemeHost(fakeSrv.URL)

	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newHandlerWithDiscovery(repo, partyRepo, fakeSrv, nil)

	// Wire sets must-exchange-token, but owner lacks capability: reject.
	body := shareBodyWithOwnerHost(ownerHost, true)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code == http.StatusCreated {
		t.Fatalf("expected rejection, got %d: %s", w.Code, w.Body.String())
	}
}

// TestReceiverClassification_DiscoveryFailure_PlainShare verifies that when
// owner discovery fails and the wire does NOT claim must-exchange-token,
// the share is accepted as legacy (both flags false).
func TestReceiverClassification_DiscoveryFailure_PlainShare(t *testing.T) {
	// Server that returns 500 to simulate discovery failure
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer failSrv.Close()

	ownerHost := stripSchemeHost(failSrv.URL)

	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newHandlerWithDiscovery(repo, partyRepo, failSrv, nil)

	body := shareBodyWithOwnerHost(ownerHost, false)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for discovery-failed plain share, got %d: %s", w.Code, w.Body.String())
	}

	shares, _ := repo.ListByRecipientUserID(context.Background(), "user-a-uuid")
	if len(shares) != 1 {
		t.Fatalf("expected 1 share, got %d", len(shares))
	}
	if shares[0].MustExchangeToken {
		t.Error("discovery failed, plain share: expected MustExchangeToken=false")
	}
}

// TestReceiverClassification_DiscoveryFailure_WithMustExchange verifies that
// when owner discovery fails and the wire claims must-exchange-token,
// the share is rejected (we cannot verify the claim without discovery).
func TestReceiverClassification_DiscoveryFailure_WithMustExchange(t *testing.T) {
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer failSrv.Close()

	ownerHost := stripSchemeHost(failSrv.URL)

	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newHandlerWithDiscovery(repo, partyRepo, failSrv, nil)

	body := shareBodyWithOwnerHost(ownerHost, true)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	// Should be rejected because we cannot verify the exchange claim
	if w.Code == http.StatusCreated {
		t.Fatal("expected rejection for must-exchange-token share when discovery fails")
	}
}

// TestReceiverClassification_NoDiscoveryClient_PassthroughWire verifies the
// fallback when no discovery client is configured at all: strict claims are
// rejected because capability cannot be verified.
func TestReceiverClassification_NoDiscoveryClient_PassthroughWire(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	// newTestHandler passes nil for discoveryClient
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "no-disc-test",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "webdav",
			"webdav": {
				"uri": "abc123",
				"sharedSecret": "secret123",
				"permissions": ["read"],
				"requirements": ["must-exchange-token"]
			}
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code == http.StatusCreated {
		t.Fatalf("expected rejection when no discovery client is available, got %d: %s", w.Code, w.Body.String())
	}
}

func TestReceiverClassification_ReceiverStrictRequiresWireMustExchange(t *testing.T) {
	fakeSrv := fakeDiscoveryServer(
		[]string{"exchange-token"},
		[]string{}, // remote criteria is not the strictness owner
	)
	defer fakeSrv.Close()

	ownerHost := stripSchemeHost(fakeSrv.URL)
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	tokenExchangeEnabled := true
	cfg := &config.Config{
		TokenExchange:        config.TokenExchangeConfig{Enabled: &tokenExchangeEnabled, Path: "token"},
		RequireTokenExchange: true,
		PeerPolicy:           "legacy",
	}
	handler := newHandlerWithDiscovery(repo, partyRepo, fakeSrv, policy.NewOpenCloudMeshPolicy(cfg))

	body := shareBodyWithOwnerHost(ownerHost, false)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code == http.StatusCreated {
		t.Fatalf("expected rejection for strict receiver without wire must-exchange-token, got %d", w.Code)
	}
}
