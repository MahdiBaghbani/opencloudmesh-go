// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package crypto_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
)

func TestCanonicalTargetURI_ConsistentWithAndWithoutURLScheme(t *testing.T) {
	withScheme := httptest.NewRequest(http.MethodPost, "https://example.com/ocm/shares?x=1", nil)
	withScheme.Host = "example.com"

	want := "https://example.com/ocm/shares?x=1"
	if got := crypto.CanonicalTargetURI(withScheme); got != want {
		t.Fatalf("with scheme: got %q want %q", got, want)
	}

	// Proxy-style request: path-only URL, Host set, no TLS -> http form.
	without := httptest.NewRequest(http.MethodPost, "/ocm/shares?x=1", nil)
	without.Host = "example.com"
	without.URL.Scheme = ""
	without.URL.Host = ""

	got := crypto.CanonicalTargetURI(without)
	if got != "http://example.com/ocm/shares?x=1" {
		t.Fatalf("without scheme: got %q", got)
	}
}

func TestBuildSignatureBase_RejectsCRLFInComponent(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://example.com/ocm/shares", nil)
	req.Header.Set("date", "Fri, 16 Jan 2026 13:37:00 GMT\r\nX-Injected: 1")

	_, err := crypto.BuildSignatureBase(req, []string{"@method", "date"})
	if err == nil {
		t.Fatal("expected CR/LF rejection")
	}
}
