package shares_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// TestOutgoing_NilCodeFlow_EmptyRequirements confirms a nil CodeFlow leaves
// webdav requirements empty on the create path (strict-off Includes).
func TestOutgoing_NilCodeFlow_EmptyRequirements(t *testing.T) {
	srv, postCount, captured := makeCapturingReceiverTLSServer([]string{"exchange-token"}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	handler := outgoingshares.NewHandler(
		repo,
		discClient,
		ctxClient,
		makeTestSigner(t),
		testProvider,
		testCurrentUser(user),
		testLogger,
	)
	handler.SetAllowedPaths([]string{"/tmp"})
	handler.SetPeerOrigin(peerorigin.NewResolver(false))
	// Intentionally leave CodeFlow unset (nil).

	tmpFile := createTempShareFile(t, "outgoing-nil-codeflow-*")
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
	if len(captured.Protocol.WebDAV.Requirements) != 0 {
		t.Fatalf("expected empty requirements for nil CodeFlow, got %v", captured.Protocol.WebDAV.Requirements)
	}
	if captured.Protocol.WebDAV.HasRequirement(spec.RequirementMustExchangeToken) {
		t.Fatal("expected no must-exchange-token requirement when CodeFlow is nil")
	}
}
