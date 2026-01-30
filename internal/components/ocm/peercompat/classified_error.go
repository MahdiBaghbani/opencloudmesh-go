// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

import (
	"errors"
	"fmt"
)

// Reason codes for strict failures that may trigger quirk attempts.
// These are stable identifiers for classifying why a strict attempt failed.
const (
	// Signature-related failures
	ReasonSignatureRequired     = "signature_required"
	ReasonSignatureInvalid      = "signature_invalid"
	ReasonSignatureMismatch     = "signature_mismatch"
	ReasonDigestMismatch        = "digest_mismatch"
	ReasonKeyIDMismatch         = "keyid_mismatch"
	ReasonKeyNotFound           = "key_not_found"

	// Token exchange failures
	ReasonTokenExchangeFailed   = "token_exchange_failed"
	ReasonTokenInvalidFormat    = "token_invalid_format"
	ReasonTokenExpired          = "token_expired"

	// Discovery failures
	ReasonDiscoveryFailed       = "discovery_failed"
	ReasonDiscoveryTimeout      = "discovery_timeout"
	ReasonPeerCapabilityMissing = "peer_capability_missing"

	// Network failures
	ReasonNetworkError          = "network_error"
	ReasonPeerUnreachable       = "peer_unreachable"
	ReasonSSRFBlocked           = "ssrf_blocked"
	ReasonTLSError              = "tls_error"

	// Protocol failures
	ReasonProtocolMismatch      = "protocol_mismatch"
	ReasonUnsupportedVersion    = "unsupported_version"

	// Remote access
	ReasonRemoteError           = "remote_error"

	// Unknown/unclassified
	ReasonUnknown               = "unknown"
)

// ClassifiedError wraps an error with a reason code for orchestration decisions.
type ClassifiedError struct {
	ReasonCode string
	Message    string
	Cause      error
}

func (e *ClassifiedError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.ReasonCode, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.ReasonCode, e.Message)
}

func (e *ClassifiedError) Unwrap() error {
	return e.Cause
}

// NewClassifiedError creates a new classified error.
func NewClassifiedError(reasonCode, message string, cause error) *ClassifiedError {
	return &ClassifiedError{
		ReasonCode: reasonCode,
		Message:    message,
		Cause:      cause,
	}
}

// ClassifyError attempts to classify an error into a reason code.
// Returns ReasonUnknown if the error cannot be classified.
func ClassifyError(err error) string {
	if err == nil {
		return ""
	}

	// Check for ClassifiedError directly
	var ce *ClassifiedError
	if errors.As(err, &ce) {
		return ce.ReasonCode
	}

	// Check error message patterns for common cases
	errStr := err.Error()

	// Signature-related
	if containsAny(errStr, "signature required", "missing signature") {
		return ReasonSignatureRequired
	}
	if containsAny(errStr, "signature invalid", "signature verification failed", "invalid signature") {
		return ReasonSignatureInvalid
	}
	if containsAny(errStr, "signature mismatch", "signer mismatch") {
		return ReasonSignatureMismatch
	}
	if containsAny(errStr, "digest mismatch", "content-digest") {
		return ReasonDigestMismatch
	}
	if containsAny(errStr, "keyid mismatch", "key id mismatch") {
		return ReasonKeyIDMismatch
	}
	if containsAny(errStr, "key not found", "public key not found") {
		return ReasonKeyNotFound
	}

	// Token exchange
	if containsAny(errStr, "token exchange failed") {
		return ReasonTokenExchangeFailed
	}
	if containsAny(errStr, "token invalid", "invalid token format") {
		return ReasonTokenInvalidFormat
	}
	if containsAny(errStr, "token expired") {
		return ReasonTokenExpired
	}

	// Discovery
	if containsAny(errStr, "discovery failed", "discovery error") {
		return ReasonDiscoveryFailed
	}
	if containsAny(errStr, "discovery timeout") {
		return ReasonDiscoveryTimeout
	}
	if containsAny(errStr, "capability not found", "capability missing") {
		return ReasonPeerCapabilityMissing
	}

	// Network
	if containsAny(errStr, "connection refused", "no such host", "network unreachable") {
		return ReasonNetworkError
	}
	if containsAny(errStr, "peer unreachable", "host unreachable") {
		return ReasonPeerUnreachable
	}
	if containsAny(errStr, "ssrf", "private ip", "loopback") {
		return ReasonSSRFBlocked
	}
	if containsAny(errStr, "tls", "certificate") {
		return ReasonTLSError
	}

	// Protocol
	if containsAny(errStr, "protocol mismatch", "unsupported protocol") {
		return ReasonProtocolMismatch
	}
	if containsAny(errStr, "unsupported version", "version mismatch") {
		return ReasonUnsupportedVersion
	}

	return ReasonUnknown
}

// containsAny checks if s contains any of the given substrings (case-insensitive).
func containsAny(s string, patterns ...string) bool {
	sLower := toLower(s)
	for _, p := range patterns {
		if contains(sLower, toLower(p)) {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
