// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleStart_PersistsTypedOCMID(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)

	createReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/start",
		bytes.NewReader(mustJSON(t, map[string]string{"target": "mahdi@ponder.org"})),
	)
	createRec := httptest.NewRecorder()
	h.HandleStart(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201 body %s", createRec.Code, createRec.Body.String())
	}

	row := loadCreatedRun(t, store, createRec)
	if row.TargetOrigin != "https://ponder.org" {
		t.Fatalf("TargetOrigin = %q, want https://ponder.org", row.TargetOrigin)
	}

	if row.TargetHost != "ponder.org" {
		t.Fatalf("TargetHost = %q, want ponder.org", row.TargetHost)
	}

	if row.RemoteOCMID == nil || *row.RemoteOCMID != "mahdi@ponder.org" {
		t.Fatalf("RemoteOCMID = %v, want mahdi@ponder.org", row.RemoteOCMID)
	}
}

func TestHandleStart_URLLeavesRemoteOCMIDNull(t *testing.T) {
	t.Parallel()

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)

	createReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/start",
		bytes.NewReader(mustJSON(t, map[string]string{"target": "https://peer.example:8443"})),
	)
	createRec := httptest.NewRecorder()
	h.HandleStart(createRec, createReq)

	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201 body %s", createRec.Code, createRec.Body.String())
	}

	row := loadCreatedRun(t, store, createRec)
	if row.TargetOrigin != "https://peer.example:8443" {
		t.Fatalf("TargetOrigin = %q, want https://peer.example:8443", row.TargetOrigin)
	}

	if row.TargetHost != "peer.example:8443" {
		t.Fatalf("TargetHost = %q, want peer.example:8443", row.TargetHost)
	}

	if row.RemoteOCMID != nil {
		t.Fatalf("RemoteOCMID = %v, want nil", row.RemoteOCMID)
	}
}

func TestHandleStart_RejectsURLUserinfo(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)
	createReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/start",
		bytes.NewReader(mustJSON(t, map[string]string{"target": "https://alice@peer.example"})),
	)
	createRec := httptest.NewRecorder()
	h.HandleStart(createRec, createReq)

	assertJSONError(t, createRec, "invalid_request")
	assertBodyOmitsSecrets(t, createRec.Body.String(), "https://alice@peer.example")
}

func TestHandleStart_MalformedURLUserinfoDoesNotEchoSecrets(t *testing.T) {
	t.Parallel()

	const raw = "https://alice:secret@[::1"

	h := NewHandler(openHandlerTestStore(t), nil)
	createReq := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/start",
		bytes.NewReader(mustJSON(t, map[string]string{"target": raw})),
	)
	createRec := httptest.NewRecorder()
	h.HandleStart(createRec, createReq)

	if createRec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body %s", createRec.Code, createRec.Body.String())
	}

	body := createRec.Body.String()
	assertBodyOmitsSecrets(t, body, raw)

	var payload map[string]string
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&payload); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if payload["error"] != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", payload["error"])
	}

	if payload["message"] != errInvalidTarget.Error() {
		t.Fatalf("message = %q, want %q", payload["message"], errInvalidTarget.Error())
	}

	okURL := httptest.NewRecorder()
	h.HandleStart(
		okURL,
		httptest.NewRequestWithContext(
			t.Context(),
			http.MethodPost,
			"/start",
			bytes.NewReader(mustJSON(t, map[string]string{"target": "https://peer.example:8443"})),
		),
	)

	if okURL.Code != http.StatusCreated {
		t.Fatalf("https URL status = %d, want 201 body %s", okURL.Code, okURL.Body.String())
	}

	okOCM := httptest.NewRecorder()
	h.HandleStart(
		okOCM,
		httptest.NewRequestWithContext(
			t.Context(),
			http.MethodPost,
			"/start",
			bytes.NewReader(mustJSON(t, map[string]string{"target": "mahdi@ponder.org"})),
		),
	)

	if okOCM.Code != http.StatusCreated {
		t.Fatalf("OCM id status = %d, want 201 body %s", okOCM.Code, okOCM.Body.String())
	}
}

func assertBodyOmitsSecrets(t *testing.T, body, raw string) {
	t.Helper()

	for _, leak := range []string{"secret", "alice", raw} {
		if leak != "" && strings.Contains(body, leak) {
			t.Fatalf("response leaked %q: %s", leak, body)
		}
	}
}
