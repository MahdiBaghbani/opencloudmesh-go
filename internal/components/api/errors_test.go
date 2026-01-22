// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
)

func TestWriteError_EnvelopeShape(t *testing.T) {
	w := httptest.NewRecorder()

	api.WriteError(w, http.StatusForbidden, api.ReasonSSRFBlocked, "connection to private IP blocked")

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}

	var envelope api.ErrorEnvelope
	if err := json.NewDecoder(w.Body).Decode(&envelope); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if envelope.Error.Code != "Forbidden" {
		t.Errorf("expected code 'Forbidden', got %q", envelope.Error.Code)
	}
	if envelope.Error.ReasonCode != api.ReasonSSRFBlocked {
		t.Errorf("expected reason_code %q, got %q", api.ReasonSSRFBlocked, envelope.Error.ReasonCode)
	}
	if envelope.Error.Message != "connection to private IP blocked" {
		t.Errorf("unexpected message: %q", envelope.Error.Message)
	}
}

func TestWriteError_StableReasonCodes(t *testing.T) {
	// Verify reason codes are stable (these should not change across versions)
	codes := map[string]string{
		"unauthenticated":     api.ReasonUnauthenticated,
		"signature_required":  api.ReasonSignatureRequired,
		"signature_invalid":   api.ReasonSignatureInvalid,
		"ssrf_blocked":        api.ReasonSSRFBlocked,
		"rate_limited":        api.ReasonRateLimited,
		"not_found":           api.ReasonNotFound,
		"internal_error":      api.ReasonInternalError,
	}

	for expected, actual := range codes {
		if actual != expected {
			t.Errorf("reason code constant changed: expected %q, got %q", expected, actual)
		}
	}
}

func TestWriteUnauthorized(t *testing.T) {
	w := httptest.NewRecorder()
	api.WriteUnauthorized(w, api.ReasonSessionExpired, "session has expired")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", w.Code)
	}

	var envelope api.ErrorEnvelope
	json.NewDecoder(w.Body).Decode(&envelope)
	if envelope.Error.ReasonCode != api.ReasonSessionExpired {
		t.Errorf("expected reason_code %q, got %q", api.ReasonSessionExpired, envelope.Error.ReasonCode)
	}
}

func TestWriteForbidden(t *testing.T) {
	w := httptest.NewRecorder()
	api.WriteForbidden(w, api.ReasonDeniedByDenylist, "peer is on denylist")

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}
}

func TestWriteTooManyRequests(t *testing.T) {
	w := httptest.NewRecorder()
	api.WriteTooManyRequests(w, "too many requests")

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", w.Code)
	}

	var envelope api.ErrorEnvelope
	json.NewDecoder(w.Body).Decode(&envelope)
	if envelope.Error.ReasonCode != api.ReasonRateLimited {
		t.Errorf("expected reason_code %q, got %q", api.ReasonRateLimited, envelope.Error.ReasonCode)
	}
}

func TestWriteNotImplemented(t *testing.T) {
	w := httptest.NewRecorder()
	api.WriteNotImplemented(w, "WebDAV LOCK")

	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected status 501, got %d", w.Code)
	}

	var envelope api.ErrorEnvelope
	json.NewDecoder(w.Body).Decode(&envelope)
	if envelope.Error.ReasonCode != api.ReasonNotImplemented {
		t.Errorf("expected reason_code %q, got %q", api.ReasonNotImplemented, envelope.Error.ReasonCode)
	}
	if envelope.Error.Message != "WebDAV LOCK not implemented yet" {
		t.Errorf("unexpected message: %q", envelope.Error.Message)
	}
}
