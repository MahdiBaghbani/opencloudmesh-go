package incoming_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func newTestHandlerWithResolver(
	repo *sharesinbox.MemoryIncomingShareRepo,
	partyRepo identity.PartyRepo,
	resolver *policy.PeerMappingResolver,
) *incoming.Handler {
	return incoming.NewHandler(
		repo,
		partyRepo,
		nil, // no policy engine
		"localhost:9200",
		"https",
		resolver,
		testLogger(),
	)
}
func TestCreateShare_NilResolver_RejectsEmptyWebDAVRequirements(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "nil-wdav-empty",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"], "requirements": []}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "INVALID_PROTOCOL" {
		t.Errorf("expected INVALID_PROTOCOL, got %q", resp.Message)
	}
	found := false
	for _, e := range resp.ValidationErrors {
		if e.Name == "protocol.webdav.requirements" && e.Message == "REQUIRED" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected validationError {protocol.webdav.requirements, REQUIRED}, got %v", resp.ValidationErrors)
	}
}

func TestCreateShare_NilResolver_RejectsEmptyWebappRequirements(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "nil-wapp-empty",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "multi", "webapp": {"uri": "https://sender.com/apps/files/abc", "targets": ["blank"], "permissions": ["view"], "requirements": [], "sharedSecret": "s"}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "INVALID_PROTOCOL" {
		t.Errorf("expected INVALID_PROTOCOL, got %q", resp.Message)
	}
	if len(resp.ValidationErrors) != 1 {
		t.Fatalf("expected exactly one validation error, got %d: %v", len(resp.ValidationErrors), resp.ValidationErrors)
	}
	if resp.ValidationErrors[0].Name != "protocol.webapp.requirements" || resp.ValidationErrors[0].Message != "REQUIRED" {
		t.Errorf("expected {protocol.webapp.requirements, REQUIRED}, got %v", resp.ValidationErrors[0])
	}
}

func TestCreateShare_ResolverWithNoPeerOverlay_RejectsEmptyWebDAVRequirements(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandlerWithResolver(repo, partyRepo, policy.NewPeerMappingResolver(policy.NewCodeFlow(), nil, config.CompatibilityScopeGlobal))

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "nonnil-wdav-empty",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"], "requirements": []}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "INVALID_PROTOCOL" {
		t.Errorf("expected INVALID_PROTOCOL, got %q", resp.Message)
	}
	if len(resp.ValidationErrors) != 1 {
		t.Fatalf("expected exactly one validation error, got %d: %v", len(resp.ValidationErrors), resp.ValidationErrors)
	}
	if resp.ValidationErrors[0].Name != "protocol.webdav.requirements" || resp.ValidationErrors[0].Message != "REQUIRED" {
		t.Errorf("expected {protocol.webdav.requirements, REQUIRED}, got %v", resp.ValidationErrors[0])
	}
}

func TestCreateShare_NilResolver_AcceptsWebDAVWithMustExchangeToken(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "nil-wdav-token",
		"owner": "owner@sender.com",
		"sender": "sender@sender.com",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"], "requirements": ["must-exchange-token"]}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func peerMappingConfigWithInstanceRequires(host string, requires bool) *config.PeerMappingConfig {
	return &config.PeerMappingConfig{
		Platform: map[string]config.PeerPlatformOverlay{
			"platform-a": {
				Instance: map[string]config.PeerMappingInstanceOverlay{
					host: {
						RequiresTokenExchangeRequirement: &requires,
					},
				},
			},
		},
	}
}

func TestCreateShare_PeerOverlayOmitsRequirementForMatchedHost(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	const matchedHost = "sender.example.com"
	const unmatchedHost = "other.example.com"

	cfg := peerMappingConfigWithInstanceRequires(matchedHost, false)
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), cfg, config.CompatibilityScopeGlobal)
	handler := newTestHandlerWithResolver(repo, partyRepo, resolver)

	bodyFor := func(host string) string {
		return `{
			"shareWith": "alice@localhost:9200",
			"name": "test.txt",
			"providerId": "overlay-omit",
			"owner": "owner@` + host + `",
			"sender": "sender@` + host + `",
			"shareType": "user",
			"resourceType": "file",
			"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"], "requirements": []}}
		}`
	}

	matchedReq := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(bodyFor(matchedHost)))
	matchedReq.Header.Set("Content-Type", "application/json")
	matchedW := httptest.NewRecorder()
	handler.CreateShare(matchedW, matchedReq)
	if matchedW.Code != http.StatusCreated {
		t.Fatalf("matched host: expected 201, got %d: %s", matchedW.Code, matchedW.Body.String())
	}

	unmatchedReq := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(bodyFor(unmatchedHost)))
	unmatchedReq.Header.Set("Content-Type", "application/json")
	unmatchedW := httptest.NewRecorder()
	handler.CreateShare(unmatchedW, unmatchedReq)
	if unmatchedW.Code != http.StatusBadRequest {
		t.Fatalf("unmatched host: expected 400, got %d: %s", unmatchedW.Code, unmatchedW.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(unmatchedW.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "INVALID_PROTOCOL" {
		t.Errorf("expected INVALID_PROTOCOL, got %q", resp.Message)
	}
	found := false
	for _, e := range resp.ValidationErrors {
		if e.Name == "protocol.webdav.requirements" && e.Message == "REQUIRED" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected validationError {protocol.webdav.requirements, REQUIRED}, got %v", resp.ValidationErrors)
	}
}

func TestCreateShare_UnknownHostUsesGlobalStrictAdmission(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	const unknownHost = "unknown.example.com"
	const boundHost = "other.example.com"

	cfg := peerMappingConfigWithInstanceRequires(boundHost, false)
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), cfg, config.CompatibilityScopeGlobal)
	handler := newTestHandlerWithResolver(repo, partyRepo, resolver)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "unknown-host",
		"owner": "owner@` + unknownHost + `",
		"sender": "sender@` + unknownHost + `",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"], "requirements": []}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown host under global strict, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "INVALID_PROTOCOL" {
		t.Errorf("expected INVALID_PROTOCOL, got %q", resp.Message)
	}
	found := false
	for _, e := range resp.ValidationErrors {
		if e.Name == "protocol.webdav.requirements" && e.Message == "REQUIRED" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected validationError {protocol.webdav.requirements, REQUIRED}, got %v", resp.ValidationErrors)
	}
}

func TestCreateShare_PeerOverlayRejectsWebappForMatchedHost(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	const matchedHost = "sender.example.com"

	cfg := peerMappingConfigWithInstanceRequires(matchedHost, false)
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), cfg, config.CompatibilityScopeGlobal)
	handler := newTestHandlerWithResolver(repo, partyRepo, resolver)

	body := validWebappShareBody("alice@localhost:9200", matchedHost, "webapp-overlay-reject")
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("matched host: expected 501 for webapp admission, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "PROTOCOL_NOT_SUPPORTED" {
		t.Errorf("expected PROTOCOL_NOT_SUPPORTED, got %q", resp.Message)
	}

	// The rejected webapp share must not be persisted; fail on any lookup
	// error other than not-found rather than silently swallowing it.
	assertShareNotStored(t, repo, matchedHost, "webapp-overlay-reject")
}

func TestCreateShare_UnknownHostRejectsWebappWithGlobalStrictAdmission(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	const matchedHost = "sender.example.com"
	const unknownHost = "unknown.example.com"

	cfg := peerMappingConfigWithInstanceRequires(matchedHost, false)
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), cfg, config.CompatibilityScopeGlobal)
	handler := newTestHandlerWithResolver(repo, partyRepo, resolver)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "webapp-resource",
		"providerId": "webapp-unknown-host",
		"owner": "owner@` + unknownHost + `",
		"sender": "sender@` + unknownHost + `",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "multi",
			"webapp": {
				"uri": "https://` + unknownHost + `/apps/files/abc",
				"targets": ["blank"],
				"permissions": ["view"],
				"requirements": [],
				"sharedSecret": "s"
			}
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown host webapp under global strict, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "INVALID_PROTOCOL" {
		t.Errorf("expected INVALID_PROTOCOL, got %q", resp.Message)
	}
	found := false
	for _, e := range resp.ValidationErrors {
		if e.Name == "protocol.webapp.requirements" && e.Message == "REQUIRED" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected validationError {protocol.webapp.requirements, REQUIRED}, got %v", resp.ValidationErrors)
	}
}

func TestCreateShare_MalformedSender_KeepsStrictRequirements(t *testing.T) {
	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	const relaxedHost = "relaxed.example.com"
	cfg := peerMappingConfigWithInstanceRequires(relaxedHost, false)
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), cfg, config.CompatibilityScopeGlobal)
	handler := newTestHandlerWithResolver(repo, partyRepo, resolver)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "malformed-sender",
		"owner": "owner@` + relaxedHost + `",
		"sender": "not-an-ocm-address",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {"name": "webdav", "webdav": {"uri": "x", "sharedSecret": "s", "permissions": ["read"], "requirements": []}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "INVALID_PROTOCOL" {
		t.Errorf("expected INVALID_PROTOCOL, got %q", resp.Message)
	}
	found := false
	for _, e := range resp.ValidationErrors {
		if e.Name == "protocol.webdav.requirements" && e.Message == "REQUIRED" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected validationError {protocol.webdav.requirements, REQUIRED}, got %v", resp.ValidationErrors)
	}
}
