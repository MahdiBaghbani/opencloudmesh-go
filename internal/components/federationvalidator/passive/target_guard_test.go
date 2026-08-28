// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestRejectNonPublicTarget(t *testing.T) {
	t.Parallel()

	reject := []struct {
		name string
		raw  string
	}{
		{name: "url ipv4 loopback", raw: "https://127.0.0.1"},
		{name: "ocm ipv4 loopback", raw: "user@127.0.0.1"},
		{name: "url ipv6 loopback", raw: "https://[::1]"},
		{name: "ocm ipv6 loopback", raw: "user@[::1]"},
		{name: "url ipv6 loopback port", raw: "https://[::1]:9200"},
		{name: "ocm ipv6 loopback port", raw: "user@[::1]:9200"},
		{name: "url link local ipv4", raw: "https://169.254.169.254"},
		{name: "ocm link local ipv4", raw: "user@169.254.169.254"},
		{name: "url private ipv4", raw: "https://10.0.0.1"},
		{name: "ocm private ipv4", raw: "user@10.0.0.1"},
		{name: "url unspecified ipv4", raw: "https://0.0.0.0"},
		{name: "ocm unspecified ipv4", raw: "user@0.0.0.0"},
		{name: "url unspecified ipv6", raw: "https://[::]"},
		{name: "ocm unspecified ipv6", raw: "user@[::]"},
		{name: "url link local ipv6", raw: "https://[fe80::1]"},
		{name: "ocm link local ipv6", raw: "user@[fe80::1]"},
		{name: "url localhost", raw: "https://localhost"},
		{name: "ocm localhost", raw: "user@localhost"},
		{name: "url localhost localdomain", raw: "https://localhost.localdomain"},
		{name: "ocm localhost localdomain", raw: "user@localhost.localdomain"},
		{name: "url localhost trailing dot", raw: "https://localhost."},
		{name: "ocm localhost trailing dot", raw: "user@localhost."},
		{name: "url localhost localdomain trailing dot", raw: "https://localhost.localdomain."},
		{name: "ocm localhost localdomain trailing dot", raw: "user@localhost.localdomain."},
	}

	for _, tt := range reject {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			parsed, err := parseTarget(tt.raw)
			if err != nil {
				t.Fatalf("parseTarget(%q): %v", tt.raw, err)
			}

			guardErr := rejectNonPublicTarget(parsed)
			if !errors.Is(guardErr, errTargetNotPublic) {
				t.Fatalf("rejectNonPublicTarget(%q) err = %v, want %v", tt.raw, guardErr, errTargetNotPublic)
			}

			if guardErr.Error() != errTargetNotPublic.Error() {
				t.Fatalf("error text = %q, want %q", guardErr.Error(), errTargetNotPublic.Error())
			}

			if strings.Contains(guardErr.Error(), tt.raw) {
				t.Fatalf("error echoed input %q: %v", tt.raw, guardErr)
			}
		})
	}
}

func TestRejectNonPublicTarget_AcceptsPublic(t *testing.T) {
	t.Parallel()

	accept := []struct {
		name string
		raw  string
	}{
		{name: "url documentation ipv4", raw: "https://203.0.113.10"},
		{name: "ocm documentation ipv4", raw: "user@203.0.113.10"},
		{name: "url example hostname", raw: "https://example.com"},
		{name: "ocm example hostname", raw: "user@example.com"},
	}

	for _, tt := range accept {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			parsed, err := parseTarget(tt.raw)
			if err != nil {
				t.Fatalf("parseTarget(%q): %v", tt.raw, err)
			}

			if guardErr := rejectNonPublicTarget(parsed); guardErr != nil {
				t.Fatalf("rejectNonPublicTarget(%q) = %v, want nil", tt.raw, guardErr)
			}
		})
	}
}

func TestHandleScan_RejectsLoopback(t *testing.T) {
	t.Parallel()

	const target = "https://127.0.0.1"

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"/api/scan?target="+target,
		nil,
	)
	rec := httptest.NewRecorder()
	h.HandleScan(rec, req)

	assertPublicAddressJSONError(t, rec, target)
	assertNoTestRuns(t, store)
}

func TestHandleStart_RejectsLoopback(t *testing.T) {
	t.Parallel()

	const target = "https://127.0.0.1"

	store := openHandlerTestStore(t)
	h := NewHandler(store, nil)

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/start",
		bytes.NewReader(mustJSON(t, map[string]string{"target": target})),
	)
	rec := httptest.NewRecorder()
	h.HandleStart(rec, req)

	assertPublicAddressJSONError(t, rec, target)
	assertNoTestRuns(t, store)
}

func assertPublicAddressJSONError(t *testing.T, rec *httptest.ResponseRecorder, raw string) {
	t.Helper()

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if strings.Contains(body, raw) {
		t.Fatalf("response echoed input %q: %s", raw, body)
	}

	var payload map[string]string
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&payload); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if payload["error"] != "target_not_public" {
		t.Fatalf("error = %q, want target_not_public", payload["error"])
	}

	if payload["message"] != errTargetNotPublic.Error() {
		t.Fatalf("message = %q, want %q", payload["message"], errTargetNotPublic.Error())
	}
}

func assertNoTestRuns(t *testing.T, store *validatorcore.Core) {
	t.Helper()

	var count int64
	if err := store.DB().WithContext(t.Context()).Model(&validatorcore.TestRun{}).Count(&count).Error; err != nil {
		t.Fatalf("count TestRun: %v", err)
	}

	if count != 0 {
		t.Fatalf("TestRun count = %d, want 0", count)
	}
}
