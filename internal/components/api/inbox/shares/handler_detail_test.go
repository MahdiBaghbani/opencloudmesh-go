// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
)

func createDetailedShareForUser(
	repo *sharesincoming.MemoryIncomingShareRepo,
	providerID, senderHost string, //nolint:unparam // test fixture helper: senderHost kept parameterized for future cases; all callers pass "sender.example.com" today
	webdavID, sharedSecret string,
	requirements []string,
) *sharesincoming.IncomingShare {
	share := &sharesincoming.IncomingShare{
		ProviderID:      providerID,
		SenderHost:      senderHost,
		ShareWith:       userAID + "@example.com",
		RecipientUserID: userAID,
		Status:          shares.ShareStatusPending,
		ResourceType:    "file",
		Name:            "test-share-" + providerID,
		Owner:           "owner@sender.example.com",
		Sender:          "sender@sender.example.com",
		ShareType:       "user",
		Permissions:     []string{"read"},
		WebDAVID:        webdavID,
		SharedSecret:    sharedSecret,
		Requirements:    requirements,
	}
	repo.Create(context.Background(), share) //nolint:errcheck // test fixture seed without testing.T

	return share
}

func TestHandleGetDetail_OwnShareReturns200(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	share := createDetailedShareForUser(repo, "prov-detail", "sender.example.com",
		"webdav-id-123", "secret-value", []string{"must-exchange-token"})

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+share.ShareID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["shareId"] != share.ShareID {
		t.Errorf("expected shareID %s, got %v", share.ShareID, resp["shareId"])
	}

	if resp["providerId"] != "prov-detail" {
		t.Errorf("expected providerID prov-detail, got %v", resp["providerId"])
	}

	if resp["name"] != share.Name {
		t.Errorf("expected name %s, got %v", share.Name, resp["name"])
	}

	if resp["senderHost"] != "sender.example.com" {
		t.Errorf("expected senderHost sender.example.com, got %v", resp["senderHost"])
	}

	// Detail-specific fields
	if resp["webdavId"] != "webdav-id-123" {
		t.Errorf("expected webdavID webdav-id-123, got %v", resp["webdavId"])
	}

	if resp["webdavUriAbsolutePresent"] != false {
		t.Errorf("expected webdavUriAbsolutePresent false (no absolute URI), got %v", resp["webdavUriAbsolutePresent"])
	}

	proto, ok := resp["protocol"].(map[string]any)
	if !ok {
		t.Fatalf("expected protocol to be an object, got %T", resp["protocol"])
	}
	// Legacy row: no protocol name was persisted, so the detail must emit an
	// empty name. It must never synthesize "multi".
	if proto["name"] != "" {
		t.Errorf("expected protocol.name empty for legacy row, got %v", proto["name"])
	}

	if _, hasWebapp := proto["webapp"]; hasWebapp {
		t.Errorf("expected no webapp arm for legacy row, got %v", proto["webapp"])
	}

	webdav, ok := proto["webdav"].(map[string]any)
	if !ok {
		t.Fatalf("expected protocol.webdav to be an object, got %T", proto["webdav"])
	}

	if webdav["uri"] != "webdav-id-123" {
		t.Errorf("expected protocol.webdav.uri webdav-id-123, got %v", webdav["uri"])
	}

	reqs, ok := webdav["requirements"].([]any)
	if !ok {
		t.Fatalf("expected requirements to be an array, got %T", webdav["requirements"])
	}

	if len(reqs) != 1 || reqs[0] != "must-exchange-token" {
		t.Errorf("expected requirements [must-exchange-token], got %v", reqs)
	}
}

func TestHandleGetDetail_CrossUserReturns404(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	share := createDetailedShareForUser(repo, "prov-cross-detail", "sender.example.com",
		"wdid", "secret", []string{})

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(repo, userB)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+share.ShareID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-user detail, got %d", w.Code)
	}
}

func TestHandleGetDetail_NonexistentReturns404(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/nonexistent-id", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleGetDetail_SharedSecretAlwaysRedacted(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	share := createDetailedShareForUser(repo, "prov-redact", "sender.example.com",
		"wdid", "real-secret-value", []string{})

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+share.ShareID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()

	if strings.Contains(body, "real-secret-value") {
		t.Error("response contains the actual SharedSecret -- must not be leaked")
	}

	if !strings.Contains(body, "[REDACTED]") {
		t.Error("response does not contain [REDACTED] for sharedSecret")
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	proto, ok := resp["protocol"].(map[string]any)
	if !ok {
		t.Fatal("expected proto type map[string]any")
	}

	webdav, ok := proto["webdav"].(map[string]any)
	if !ok {
		t.Fatal("expected webdav type map[string]any")
	}

	if webdav["sharedSecret"] != "[REDACTED]" {
		t.Errorf("expected sharedSecret [REDACTED], got %v", webdav["sharedSecret"])
	}
}

func TestHandleGetDetail_RecipientUserIDNotInResponse(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	share := createDetailedShareForUser(repo, "prov-noleak", "sender.example.com",
		"wdid", "secret", []string{})

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+share.ShareID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	body := w.Body.String()

	if strings.Contains(body, "recipientUserID") || strings.Contains(body, "RecipientUserID") {
		t.Error("response contains RecipientUserID field name -- must not be leaked")
	}

	if strings.Contains(body, "recipientDisplayName") || strings.Contains(body, "RecipientDisplayName") {
		t.Error("response contains RecipientDisplayName field name -- must not be leaked")
	}
}

func TestHandleGetDetail_RequirementsReflectStoredValues(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}

	shareA := createDetailedShareForUser(repo, "prov-met-true", "sender.example.com",
		"wdid", "secret", []string{"must-exchange-token"})

	router := newTestRouter(repo, userA)

	reqA := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+shareA.ShareID, nil)
	wA := httptest.NewRecorder()
	router.ServeHTTP(wA, reqA)

	var respA map[string]any
	if err := json.Unmarshal(wA.Body.Bytes(), &respA); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	protoA, ok := respA["protocol"].(map[string]any)
	if !ok {
		t.Fatal("expected protoA type map[string]any")
	}

	webdavA, ok := protoA["webdav"].(map[string]any)
	if !ok {
		t.Fatal("expected webdavA type map[string]any")
	}

	reqsA, ok := webdavA["requirements"].([]any)
	if !ok {
		t.Fatalf("expected requirements to be an array, got %T", webdavA["requirements"])
	}

	if len(reqsA) != 1 || reqsA[0] != "must-exchange-token" {
		t.Errorf("expected requirements [must-exchange-token], got %v", reqsA)
	}

	shareB := createDetailedShareForUser(repo, "prov-met-false", "sender.example.com",
		"wdid2", "secret2", []string{})

	reqB := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+shareB.ShareID, nil)
	wB := httptest.NewRecorder()
	router.ServeHTTP(wB, reqB)

	var respB map[string]any
	if err := json.Unmarshal(wB.Body.Bytes(), &respB); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	protoB, ok := respB["protocol"].(map[string]any)
	if !ok {
		t.Fatal("expected protoB type map[string]any")
	}

	webdavB, ok := protoB["webdav"].(map[string]any)
	if !ok {
		t.Fatal("expected webdavB type map[string]any")
	}

	reqsB, ok := webdavB["requirements"].([]any)
	if !ok {
		t.Fatalf("expected requirements to be an array, got %T", webdavB["requirements"])
	}

	if len(reqsB) != 0 {
		t.Errorf("expected empty requirements, got %v", reqsB)
	}
}

func TestHandleGetDetail_Unauthenticated(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	router := newTestRouter(repo, nil)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/some-id", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleGetDetail_NilPermissionsSerializesAsEmptyArray(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()

	share := &sharesincoming.IncomingShare{
		ProviderID:      "prov-nilperms",
		SenderHost:      "sender.example.com",
		ShareWith:       userAID + "@example.com",
		RecipientUserID: userAID,
		Status:          shares.ShareStatusPending,
		ResourceType:    "file",
		Name:            "test-share-nilperms",
		Owner:           "owner@sender.example.com",
		Sender:          "sender@sender.example.com",
		ShareType:       "user",
		WebDAVID:        "wdid",
		SharedSecret:    "secret",
	}
	if err := repo.Create(context.Background(), share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+share.ShareID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	proto, ok := resp["protocol"].(map[string]any)
	if !ok {
		t.Fatal("expected proto type map[string]any")
	}

	webdav, ok := proto["webdav"].(map[string]any)
	if !ok {
		t.Fatal("expected webdav type map[string]any")
	}

	perms, ok := webdav["permissions"].([]any)
	if !ok {
		t.Fatalf("expected permissions to be an array, got %T (likely null)", webdav["permissions"])
	}

	if len(perms) != 0 {
		t.Errorf("expected empty permissions array, got %v", perms)
	}
}

func TestHandleGetDetail_AbsoluteWebDAVURIPresent(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(repo, userA)

	shareA := createDetailedShareForUser(repo, "prov-abs-yes", "sender.example.com",
		"https://sender.example.com/webdav/file.txt", "secret", []string{})

	reqA := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+shareA.ShareID, nil)
	wA := httptest.NewRecorder()
	router.ServeHTTP(wA, reqA)

	var respA map[string]any
	if err := json.Unmarshal(wA.Body.Bytes(), &respA); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if respA["webdavUriAbsolutePresent"] != true {
		t.Errorf("expected webdavUriAbsolutePresent true, got %v", respA["webdavUriAbsolutePresent"])
	}

	protoA, ok := respA["protocol"].(map[string]any)
	if !ok {
		t.Fatal("expected protoA type map[string]any")
	}

	webdavA, ok := protoA["webdav"].(map[string]any)
	if !ok {
		t.Fatal("expected webdavA type map[string]any")
	}

	if webdavA["uri"] != "https://sender.example.com/webdav/file.txt" {
		t.Errorf("expected absolute URI in protocol.webdav.uri, got %v", webdavA["uri"])
	}

	shareB := createDetailedShareForUser(repo, "prov-abs-no", "sender.example.com",
		"relative-id-only", "secret2", []string{})

	reqB := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+shareB.ShareID, nil)
	wB := httptest.NewRecorder()
	router.ServeHTTP(wB, reqB)

	var respB map[string]any
	if err := json.Unmarshal(wB.Body.Bytes(), &respB); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if respB["webdavUriAbsolutePresent"] != false {
		t.Errorf("expected webdavUriAbsolutePresent false, got %v", respB["webdavUriAbsolutePresent"])
	}

	protoB, ok := respB["protocol"].(map[string]any)
	if !ok {
		t.Fatal("expected protoB type map[string]any")
	}

	webdavB, ok := protoB["webdav"].(map[string]any)
	if !ok {
		t.Fatal("expected webdavB type map[string]any")
	}

	if webdavB["uri"] != "relative-id-only" {
		t.Errorf("expected WebDAVID as uri, got %v", webdavB["uri"])
	}
}

// TestHandleGetDetail_RendersProtocolNameAndWebappArm verifies the inbox
// detail HTTP response renders the stored protocol.name and all webapp arm
// fields. It uses an in-memory repo and exercises the handler -> detail view
// rendering path. The durable store -> adapter round-trip is covered by
// TestIncomingShareAdapter_DurableRoundTrip_PersistsProtocolNameAndWebappArm.
// Legacy rows (no protocol name, no webapp data) emit an empty name and omit
// the webapp arm; that case is covered by TestHandleGetDetail_OwnShareReturns200.
func TestHandleGetDetail_RendersProtocolNameAndWebappArm(t *testing.T) {
	repo := sharesincoming.NewMemoryIncomingShareRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}

	share := &sharesincoming.IncomingShare{
		ProviderID:        "prov-webapp-arm",
		SenderHost:        "sender.example.com",
		ShareWith:         userAID + "@example.com",
		RecipientUserID:   userAID,
		Status:            shares.ShareStatusPending,
		ResourceType:      "file",
		Name:              "test-share-webapp",
		Owner:             "owner@sender.example.com",
		Sender:            "sender@sender.example.com",
		ShareType:         "user",
		Permissions:       []string{"read"},
		WebDAVID:          "wdid-webapp",
		SharedSecret:      "secret",
		Requirements:      []string{"must-exchange-token"},
		ProtocolName:      "custom-app",
		WebappURI:         "https://app.sender.example.com/launch",
		WebappTargets:     []string{"blank", "_self"},
		WebappPermissions: []string{"view", "share"},
	}
	if err := repo.Create(context.Background(), share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	router := newTestRouter(repo, userA)
	req := httptest.NewRequest(http.MethodGet, "/inbox/shares/"+share.ShareID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	proto, ok := resp["protocol"].(map[string]any)
	if !ok {
		t.Fatalf("expected protocol to be an object, got %T", resp["protocol"])
	}

	if proto["name"] != "custom-app" {
		t.Errorf("expected protocol.name custom-app, got %v", proto["name"])
	}

	webapp, ok := proto["webapp"].(map[string]any)
	if !ok {
		t.Fatalf("expected protocol.webapp to be an object, got %T", proto["webapp"])
	}

	if webapp["uri"] != "https://app.sender.example.com/launch" {
		t.Errorf("expected webapp.uri %q, got %v", "https://app.sender.example.com/launch", webapp["uri"])
	}

	targets, ok := webapp["targets"].([]any)
	if !ok {
		t.Fatalf("expected webapp.targets to be an array, got %T", webapp["targets"])
	}

	if len(targets) != 2 || targets[0] != "blank" || targets[1] != "_self" {
		t.Errorf("expected webapp.targets [blank _self], got %v", targets)
	}

	perms, ok := webapp["permissions"].([]any)
	if !ok {
		t.Fatalf("expected webapp.permissions to be an array, got %T", webapp["permissions"])
	}

	if len(perms) != 2 || perms[0] != "view" || perms[1] != "share" {
		t.Errorf("expected webapp.permissions [view share], got %v", perms)
	}

	// WebDAV arm must remain present and unchanged alongside the webapp arm.
	webdav, ok := proto["webdav"].(map[string]any)
	if !ok {
		t.Fatalf("expected protocol.webdav to still be present, got %T", proto["webdav"])
	}

	if webdav["uri"] != "wdid-webapp" {
		t.Errorf("expected webdav.uri wdid-webapp, got %v", webdav["uri"])
	}
}
