// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package http_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestMustClose_closesWithoutError(t *testing.T) {
	body := io.NopCloser(nil)
	tshttp.MustClose(t, body)
}

func TestMustEncodeJSON_writesPayload(t *testing.T) {
	rec := httptest.NewRecorder()
	tshttp.MustEncodeJSON(t, rec, map[string]string{"ok": "true"})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	if rec.Body.String() != "{\"ok\":\"true\"}\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestMustMarshalJSON_returnsBytes(t *testing.T) {
	got := tshttp.MustMarshalJSON(t, map[string]int{"n": 1})
	if string(got) != "{\"n\":1}" {
		t.Fatalf("got %q", string(got))
	}
}

func TestWriteJSON_writesPayload(t *testing.T) {
	rec := httptest.NewRecorder()
	tshttp.WriteJSON(rec, map[string]bool{"ok": true})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}
