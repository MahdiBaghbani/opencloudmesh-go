// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package accepted_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing/accepted"
)

const (
	testProvider = "example.com"
	testScheme   = "https"
)

func newTestHandler(repo invitesoutgoing.OutgoingInviteRepo, partyRepo identity.PartyRepo) *accepted.Handler {
	if partyRepo == nil {
		partyRepo = identity.NewMemoryPartyRepo()
	}

	return accepted.NewHandler(repo, partyRepo, nil, testProvider, testScheme)
}

func postInviteAccepted(handler *accepted.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/invite-accepted", bytes.NewBufferString(body))
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
