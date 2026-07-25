package incoming_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

const (
	testProvider = "example.com"
	testScheme   = "https"
)

func newTestHandler(repo invitesoutgoing.OutgoingInviteRepo, partyRepo identity.PartyRepo) *incoming.Handler {
	if partyRepo == nil {
		partyRepo = identity.NewMemoryPartyRepo()
	}
	return incoming.NewHandler(repo, partyRepo, nil, testProvider, testScheme, testLogger)
}

func postInviteAccepted(handler *incoming.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/ocm/invite-accepted", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.HandleInviteAccepted(w, req)
	return w
}

func decodeOCMError(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	return resp["message"]
}

func validAcceptedBody(token string) string {
	return `{"recipientProvider":"other.com","token":"` + token + `","userID":"u@host","email":"remote@other.com","name":"Remote User"}`
}
