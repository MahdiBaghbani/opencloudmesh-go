// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ui_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ui"
)

func TestAcceptInvite_ReadsTokenAndProviderFromQuery(t *testing.T) {
	handler, err := ui.NewHandler("", "alice.example.com")
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodGet,
		"/accept-invite?token=invite-tok&providerDomain=alice.example.com",
		nil,
	)
	w := httptest.NewRecorder()
	handler.AcceptInvite(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	for _, want := range []string{"invite-tok", "alice.example.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in accept-invite page", want)
		}
	}
}

func TestAcceptInvite_MissingParamsShowsWarning(t *testing.T) {
	handler, err := ui.NewHandler("", "alice.example.com")
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/accept-invite", nil)
	w := httptest.NewRecorder()
	handler.AcceptInvite(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "missing-params") {
		t.Error("expected missing-params element in page when query params absent")
	}

	if !strings.Contains(body, "Missing invite parameters") {
		t.Error("expected missing-params warning text")
	}
}
