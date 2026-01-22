// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package federation

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestClassifyError_ClassifiedError(t *testing.T) {
	err := NewClassifiedError(ReasonSignatureRequired, "signature is required", nil)
	result := ClassifyError(err)
	if result != ReasonSignatureRequired {
		t.Errorf("expected %s, got %s", ReasonSignatureRequired, result)
	}
}

func TestClassifyError_WrappedClassifiedError(t *testing.T) {
	inner := NewClassifiedError(ReasonTokenExpired, "token has expired", nil)

	// Test the direct case
	result := ClassifyError(inner)
	if result != ReasonTokenExpired {
		t.Errorf("expected %s, got %s", ReasonTokenExpired, result)
	}

	// Test with fmt.Errorf wrapping (preserves errors.As chain)
	wrapped := fmt.Errorf("wrapped: %w", inner)
	result = ClassifyError(wrapped)
	if result != ReasonTokenExpired {
		t.Errorf("expected %s from wrapped error, got %s", ReasonTokenExpired, result)
	}
}

func TestClassifyError_StringPatterns(t *testing.T) {
	tests := []struct {
		errMsg   string
		expected string
	}{
		{"missing signature", ReasonSignatureRequired},
		{"signature required for this request", ReasonSignatureRequired},
		{"signature verification failed", ReasonSignatureInvalid},
		{"invalid signature on request", ReasonSignatureInvalid},
		{"content-digest mismatch", ReasonDigestMismatch},
		{"keyid mismatch detected", ReasonKeyIDMismatch},
		{"public key not found", ReasonKeyNotFound},
		{"token exchange failed", ReasonTokenExchangeFailed},
		{"token expired at time", ReasonTokenExpired},
		{"discovery failed for peer", ReasonDiscoveryFailed},
		{"discovery timeout after 10s", ReasonDiscoveryTimeout},
		{"capability not found", ReasonPeerCapabilityMissing},
		{"connection refused", ReasonNetworkError},
		{"no such host", ReasonNetworkError},
		{"peer unreachable", ReasonPeerUnreachable},
		{"ssrf blocked", ReasonSSRFBlocked},
		{"private ip blocked", ReasonSSRFBlocked},
		{"tls handshake error", ReasonTLSError},
		{"certificate verify failed", ReasonTLSError},
		{"protocol mismatch", ReasonProtocolMismatch},
		{"unsupported version", ReasonUnsupportedVersion},
		{"some unknown error", ReasonUnknown},
	}

	for _, tt := range tests {
		err := errors.New(tt.errMsg)
		result := ClassifyError(err)
		if result != tt.expected {
			t.Errorf("ClassifyError(%q) = %s, expected %s", tt.errMsg, result, tt.expected)
		}
	}
}

func TestClassifyError_Nil(t *testing.T) {
	result := ClassifyError(nil)
	if result != "" {
		t.Errorf("expected empty string for nil error, got %s", result)
	}
}

func TestOrchestrator_StrictSuccess(t *testing.T) {
	registry := NewProfileRegistry(nil, nil)
	orch := NewOrchestrator(registry)

	strictCalled := false
	quirkCalled := false

	result := orch.Execute(
		context.Background(),
		"peer.example.com",
		func(ctx context.Context) error {
			strictCalled = true
			return nil // Success
		},
		func(ctx context.Context, quirk string) error {
			quirkCalled = true
			return nil
		},
	)

	if !strictCalled {
		t.Error("strict function was not called")
	}
	if quirkCalled {
		t.Error("quirk function should not be called on strict success")
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.QuirkApplied != "" {
		t.Error("no quirk should be applied on strict success")
	}
}

func TestOrchestrator_StrictFails_NoQuirkAvailable(t *testing.T) {
	// Use strict profile which has no quirks
	registry := NewProfileRegistry(nil, nil)
	orch := NewOrchestrator(registry)

	result := orch.Execute(
		context.Background(),
		"strict-peer.example.com", // No mapping -> strict profile
		func(ctx context.Context) error {
			return NewClassifiedError(ReasonSignatureRequired, "missing signature", nil)
		},
		func(ctx context.Context, quirk string) error {
			t.Fatal("quirk should not be called for strict profile")
			return nil
		},
	)

	if result.Success {
		t.Error("expected failure")
	}
	if result.ReasonCode != ReasonSignatureRequired {
		t.Errorf("expected %s, got %s", ReasonSignatureRequired, result.ReasonCode)
	}
	if result.QuirkApplied != "" {
		t.Error("no quirk should be applied for strict profile")
	}
}

func TestOrchestrator_StrictFails_QuirkApplied(t *testing.T) {
	// Use nextcloud profile which has quirks
	mappings := []ProfileMapping{
		{Pattern: "nextcloud.example.com", ProfileName: "nextcloud"},
	}
	registry := NewProfileRegistry(nil, mappings)
	orch := NewOrchestrator(registry)

	quirkApplied := ""

	result := orch.Execute(
		context.Background(),
		"nextcloud.example.com",
		func(ctx context.Context) error {
			return NewClassifiedError(ReasonSignatureRequired, "missing signature", nil)
		},
		func(ctx context.Context, quirk string) error {
			quirkApplied = quirk
			return nil // Quirk succeeds
		},
	)

	if !result.Success {
		t.Errorf("expected success after quirk, got error: %v", result.Error)
	}
	if result.ReasonCode != ReasonSignatureRequired {
		t.Errorf("expected reason %s, got %s", ReasonSignatureRequired, result.ReasonCode)
	}
	if result.QuirkApplied == "" {
		t.Error("expected a quirk to be applied")
	}
	if quirkApplied == "" {
		t.Error("quirk function should have been called")
	}
	// accept_plain_token is a quirk that applies to signature_required
	if result.QuirkApplied != "accept_plain_token" {
		t.Errorf("expected accept_plain_token quirk, got %s", result.QuirkApplied)
	}
}

func TestOrchestrator_StrictFails_QuirkAlsoFails(t *testing.T) {
	mappings := []ProfileMapping{
		{Pattern: "nextcloud.example.com", ProfileName: "nextcloud"},
	}
	registry := NewProfileRegistry(nil, mappings)
	orch := NewOrchestrator(registry)

	result := orch.Execute(
		context.Background(),
		"nextcloud.example.com",
		func(ctx context.Context) error {
			return NewClassifiedError(ReasonSignatureRequired, "missing signature", nil)
		},
		func(ctx context.Context, quirk string) error {
			return NewClassifiedError(ReasonNetworkError, "peer unreachable", nil)
		},
	)

	if result.Success {
		t.Error("expected failure when quirk also fails")
	}
	if result.QuirkApplied == "" {
		t.Error("quirk should have been attempted")
	}
	// The final reason code should be from the quirk attempt
	if result.ReasonCode != ReasonNetworkError {
		t.Errorf("expected reason from quirk failure, got %s", result.ReasonCode)
	}
}

func TestOrchestrator_QuirksNeverAppliedWithoutReasonCode(t *testing.T) {
	mappings := []ProfileMapping{
		{Pattern: "nextcloud.example.com", ProfileName: "nextcloud"},
	}
	registry := NewProfileRegistry(nil, mappings)
	orch := NewOrchestrator(registry)

	// An unknown error that doesn't match any quirk's AppliesTo
	result := orch.Execute(
		context.Background(),
		"nextcloud.example.com",
		func(ctx context.Context) error {
			return errors.New("completely unknown error type")
		},
		func(ctx context.Context, quirk string) error {
			t.Fatal("quirk should not be called for unknown reason code")
			return nil
		},
	)

	if result.Success {
		t.Error("expected failure")
	}
	if result.ReasonCode != ReasonUnknown {
		t.Errorf("expected %s, got %s", ReasonUnknown, result.ReasonCode)
	}
	if result.QuirkApplied != "" {
		t.Error("no quirk should be applied for unknown reason code")
	}
}

func TestOrchestrator_QuirksNeverAppliedWithoutProfileGate(t *testing.T) {
	// Dev profile has the quirk but we're testing without profile gate
	registry := NewProfileRegistry(nil, nil) // No mappings -> strict for all
	orch := NewOrchestrator(registry)

	// This reason code has applicable quirks, but profile doesn't allow them
	result := orch.Execute(
		context.Background(),
		"any-peer.example.com", // No mapping -> strict
		func(ctx context.Context) error {
			return NewClassifiedError(ReasonDigestMismatch, "content-digest mismatch", nil)
		},
		func(ctx context.Context, quirk string) error {
			t.Fatal("quirk should not be called for strict profile")
			return nil
		},
	)

	if result.Success {
		t.Error("expected failure")
	}
	if result.QuirkApplied != "" {
		t.Error("strict profile should not allow any quirks")
	}
}

func TestOrchestrator_CanApplyQuirk(t *testing.T) {
	mappings := []ProfileMapping{
		{Pattern: "nextcloud.example.com", ProfileName: "nextcloud"},
	}
	registry := NewProfileRegistry(nil, mappings)
	orch := NewOrchestrator(registry)

	// Nextcloud profile has accept_plain_token which applies to signature_required
	if !orch.CanApplyQuirk("nextcloud.example.com", ReasonSignatureRequired, "accept_plain_token") {
		t.Error("expected CanApplyQuirk to return true for nextcloud + signature_required + accept_plain_token")
	}

	// Nextcloud profile has skip_digest_validation which applies to digest_mismatch
	if !orch.CanApplyQuirk("nextcloud.example.com", ReasonDigestMismatch, "skip_digest_validation") {
		t.Error("expected CanApplyQuirk to return true for nextcloud + digest_mismatch + skip_digest_validation")
	}

	// Strict profile (no quirks)
	if orch.CanApplyQuirk("strict-peer.example.com", ReasonSignatureRequired, "accept_plain_token") {
		t.Error("expected CanApplyQuirk to return false for strict profile")
	}

	// Wrong reason code
	if orch.CanApplyQuirk("nextcloud.example.com", ReasonNetworkError, "accept_plain_token") {
		t.Error("expected CanApplyQuirk to return false for non-matching reason code")
	}
}

func TestBuiltinQuirks(t *testing.T) {
	quirks := BuiltinQuirks()

	// Verify we have the expected quirks
	expectedNames := []string{
		"accept_plain_token",
		"send_token_in_body",
		"skip_digest_validation",
		"allow_unsigned_discovery",
		"allow_keyid_mismatch",
	}

	for _, name := range expectedNames {
		found := false
		for _, q := range quirks {
			if q.Name == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected quirk %q not found", name)
		}
	}

	// Verify each quirk has at least one applicable reason code
	for _, q := range quirks {
		if len(q.AppliesTo) == 0 {
			t.Errorf("quirk %q has no applicable reason codes", q.Name)
		}
	}
}

func TestClassifiedError_Error(t *testing.T) {
	// Without cause
	err := NewClassifiedError(ReasonTokenExpired, "token expired", nil)
	expected := "token_expired: token expired"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}

	// With cause
	cause := errors.New("underlying error")
	errWithCause := NewClassifiedError(ReasonNetworkError, "connection failed", cause)
	expected = "network_error: connection failed: underlying error"
	if errWithCause.Error() != expected {
		t.Errorf("expected %q, got %q", expected, errWithCause.Error())
	}
}

func TestClassifiedError_Unwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := NewClassifiedError(ReasonNetworkError, "wrapper", cause)

	unwrapped := errors.Unwrap(err)
	if unwrapped != cause {
		t.Error("Unwrap should return the cause")
	}
}
