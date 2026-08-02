// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package accepted_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"
)

func TestHandleInviteAccepted_RecipientProviderRequired(t *testing.T) {
	repo := tsrepos.OpenMemory(t).OutgoingInvites
	handler := newTestHandler(repo, nil)

	w := postInviteAccepted(handler, `{"recipientProvider":"","token":"t","userID":"u@host","email":"e","name":"n"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	if msg := decodeOCMError(t, w); msg != "RECIPIENT_PROVIDER_REQUIRED" {
		t.Errorf("expected RECIPIENT_PROVIDER_REQUIRED, got %q", msg)
	}
}

func TestHandleInviteAccepted_InvalidRecipientProvider(t *testing.T) {
	repo := tsrepos.OpenMemory(t).OutgoingInvites
	handler := newTestHandler(repo, nil)

	w := postInviteAccepted(handler, `{"recipientProvider":"https://other.com","token":"t","userID":"u@host","email":"e","name":"n"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	if msg := decodeOCMError(t, w); msg != "INVALID_RECIPIENT_PROVIDER" {
		t.Errorf("expected INVALID_RECIPIENT_PROVIDER, got %q", msg)
	}
}

func TestHandleInviteAccepted_TokenRequired(t *testing.T) {
	repo := tsrepos.OpenMemory(t).OutgoingInvites
	handler := newTestHandler(repo, nil)

	w := postInviteAccepted(handler, `{"recipientProvider":"other.com","token":"","userID":"u@host","email":"e","name":"n"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	if msg := decodeOCMError(t, w); msg != "TOKEN_REQUIRED" {
		t.Errorf("expected TOKEN_REQUIRED, got %q", msg)
	}
}

func TestHandleInviteAccepted_UserIDRequired(t *testing.T) {
	repo := tsrepos.OpenMemory(t).OutgoingInvites
	handler := newTestHandler(repo, nil)

	w := postInviteAccepted(handler, `{"recipientProvider":"other.com","token":"t","userID":"","email":"e","name":"n"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	if msg := decodeOCMError(t, w); msg != "USERID_REQUIRED" {
		t.Errorf("expected USERID_REQUIRED, got %q", msg)
	}
}

func TestHandleInviteAccepted_EmailKeyMissing(t *testing.T) {
	repo := tsrepos.OpenMemory(t).OutgoingInvites
	handler := newTestHandler(repo, nil)

	w := postInviteAccepted(handler, `{"recipientProvider":"other.com","token":"t","userID":"u@host","name":"n"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	if msg := decodeOCMError(t, w); msg != "EMAIL_REQUIRED" {
		t.Errorf("expected EMAIL_REQUIRED, got %q", msg)
	}
}

func TestHandleInviteAccepted_NameKeyMissing(t *testing.T) {
	repo := tsrepos.OpenMemory(t).OutgoingInvites
	handler := newTestHandler(repo, nil)

	w := postInviteAccepted(handler, `{"recipientProvider":"other.com","token":"t","userID":"u@host","email":"e"}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	if msg := decodeOCMError(t, w); msg != "NAME_REQUIRED" {
		t.Errorf("expected NAME_REQUIRED, got %q", msg)
	}
}
func TestHandleInviteAccepted_StrictContentType(t *testing.T) {
	repo := tsrepos.OpenMemory(t).OutgoingInvites
	handler := newTestHandler(repo, nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/ocm/invite-accepted",
		bytes.NewBufferString("token=abc&recipientProvider=other.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	handler.HandleInviteAccepted(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", w.Code)
	}
}
