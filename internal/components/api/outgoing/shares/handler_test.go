package shares_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// TestOutgoing_LegacyVoluntary_EmptyRequirements confirms a legacy voluntary
// code flow leaves webdav requirements empty when the receiver does not force
// token exchange.
func TestOutgoing_LegacyVoluntary_EmptyRequirements(t *testing.T) {
	srv, postCount, captured := makeCapturingReceiverTLSServer([]string{"exchange-token"}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := sharesoutgoing.NewMemoryOutgoingShareRepo()
	discClient, ctxClient := makeTLSClients()
	handler := newLegacyVoluntaryOutgoingHandler(t, repo, discClient, ctxClient, user)

	tmpFile := createTempShareFile(t, "outgoing-legacy-voluntary-*")
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
		t.Fatalf("expected empty requirements for legacy voluntary, got %v", captured.Protocol.WebDAV.Requirements)
	}
	if captured.Protocol.WebDAV.HasRequirement(spec.RequirementMustExchangeToken) {
		t.Fatal("expected no must-exchange-token requirement for legacy voluntary")
	}
}
