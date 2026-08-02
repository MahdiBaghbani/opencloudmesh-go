// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

// stubPoster returns a canned response for the invite-accepted call.
type stubPoster struct {
	status int
	body   string
	err    error
}

func (p *stubPoster) PostInviteAccepted(_ context.Context, _ string, _ []byte) (*http.Response, error) {
	if p.err != nil {
		return nil, p.err
	}

	return &http.Response{
		StatusCode: p.status,
		Body:       io.NopCloser(strings.NewReader(p.body)),
	}, nil
}

func sendTestInviteAccepted(t *testing.T, poster incoming.InviteAcceptedPoster) (incoming.AcceptResult, error) {
	t.Helper()

	return incoming.SendInviteAccepted(context.Background(), poster, spec.InviteAcceptedRequest{
		RecipientProvider: "receiver.example",
		Token:             "tok",
		UserID:            "user@receiver.example",
	}, "sender.example")
}

func TestSendInviteAccepted_OKWithIdentity(t *testing.T) {
	result, err := sendTestInviteAccepted(t, &stubPoster{
		status: http.StatusCreated,
		body:   `{"userID":"sender-user@sender.example","email":"s@example","name":"Sender"}`,
	})
	if err != nil {
		t.Fatalf("SendInviteAccepted: %v", err)
	}

	if result.AlreadyAccepted {
		t.Error("AlreadyAccepted = true, want false for 201")
	}

	if result.Response.UserID != "sender-user@sender.example" {
		t.Errorf("UserID = %q", result.Response.UserID)
	}
}

func TestSendInviteAccepted_RejectsEmptyUserIDOn200(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusCreated} {
		_, err := sendTestInviteAccepted(t, &stubPoster{status: status, body: `{"status":"ok"}`})
		if err == nil {
			t.Fatalf("status %d: expected error for empty userID, got nil", status)
		}

		if !strings.Contains(err.Error(), "missing userID") {
			t.Errorf("status %d: error = %v, want missing userID", status, err)
		}
	}
}

func TestSendInviteAccepted_ConflictWithIdentityIsIdempotentSuccess(t *testing.T) {
	result, err := sendTestInviteAccepted(t, &stubPoster{
		status: http.StatusConflict,
		body:   `{"userID":"sender-user@sender.example","email":"s@example","name":"Sender"}`,
	})
	if err != nil {
		t.Fatalf("SendInviteAccepted: %v", err)
	}

	if !result.AlreadyAccepted {
		t.Error("AlreadyAccepted = false, want true for 409 with identity")
	}

	if result.Response.UserID != "sender-user@sender.example" {
		t.Errorf("UserID = %q", result.Response.UserID)
	}
}

func TestSendInviteAccepted_ConflictWithoutIdentityIsError(t *testing.T) {
	bodies := []string{
		``,                      // bodyless
		`{"status":"conflict"}`, // empty userID
		`not-json`,              // undecodable
	}

	for _, body := range bodies {
		_, err := sendTestInviteAccepted(t, &stubPoster{status: http.StatusConflict, body: body})
		if err == nil {
			t.Errorf("body %q: expected error for 409 without identity, got nil", body)
		}
	}
}

func TestSendInviteAccepted_RejectedStatusIsError(t *testing.T) {
	_, err := sendTestInviteAccepted(t, &stubPoster{status: http.StatusBadGateway, body: "upstream down"})
	if err == nil {
		t.Fatal("expected error for 502, got nil")
	}

	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error = %v, want status in message", err)
	}
}
