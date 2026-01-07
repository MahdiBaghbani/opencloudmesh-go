// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

// Package federation provides peer federation policy, profiles, and orchestration.
package federation

import (
	"context"
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

// QuirkAttempt represents a quirk that can be attempted after a strict failure.
type QuirkAttempt struct {
	Name        string
	Description string
	AppliesTo   []string // List of reason codes this quirk can address
}

// BuiltinQuirks returns the set of known quirks for interop.
func BuiltinQuirks() []QuirkAttempt {
	return []QuirkAttempt{
		{
			Name:        "accept_plain_token",
			Description: "Accept token in request body without signature verification",
			AppliesTo:   []string{ReasonSignatureRequired, ReasonSignatureInvalid, ReasonKeyNotFound},
		},
		{
			Name:        "send_token_in_body",
			Description: "Send token in request body instead of header",
			AppliesTo:   []string{ReasonTokenExchangeFailed, ReasonProtocolMismatch},
		},
		{
			Name:        "skip_digest_validation",
			Description: "Skip Content-Digest validation on incoming requests",
			AppliesTo:   []string{ReasonDigestMismatch},
		},
		{
			Name:        "allow_unsigned_discovery",
			Description: "Accept unsigned discovery responses",
			AppliesTo:   []string{ReasonSignatureRequired, ReasonSignatureInvalid},
		},
		{
			Name:        "allow_keyid_mismatch",
			Description: "Allow keyId host to differ from declared sender",
			AppliesTo:   []string{ReasonKeyIDMismatch, ReasonSignatureMismatch},
		},
	}
}

// Orchestrator manages strict-first request orchestration with quirk fallback.
type Orchestrator struct {
	profileRegistry *ProfileRegistry
	quirks          []QuirkAttempt
}

// NewOrchestrator creates a new orchestrator with the given profile registry.
func NewOrchestrator(profileRegistry *ProfileRegistry) *Orchestrator {
	return &Orchestrator{
		profileRegistry: profileRegistry,
		quirks:          BuiltinQuirks(),
	}
}

// AttemptResult captures the result of an orchestrated attempt.
type AttemptResult struct {
	Success      bool
	ReasonCode   string
	QuirkApplied string // Name of quirk applied, empty if none
	Error        error
}

// StrictFunc is a function that performs the strict attempt.
type StrictFunc func(ctx context.Context) error

// QuirkFunc is a function that performs a quirk attempt.
// The quirk name is passed to help the function apply the right behavior.
type QuirkFunc func(ctx context.Context, quirk string) error

// Execute performs strict-first orchestration:
// 1. Try strict attempt
// 2. If strict fails, classify the error
// 3. If peer profile allows a quirk for this reason code, try exactly one quirk
// 4. Return the final result
func (o *Orchestrator) Execute(
	ctx context.Context,
	peerDomain string,
	strictFn StrictFunc,
	quirkFn QuirkFunc,
) AttemptResult {
	// Step 1: Try strict attempt
	strictErr := strictFn(ctx)
	if strictErr == nil {
		return AttemptResult{Success: true}
	}

	// Step 2: Classify the error
	reasonCode := ClassifyError(strictErr)

	// Step 3: Check if peer profile allows any quirk for this reason
	profile := o.profileRegistry.GetProfile(peerDomain)

	// Find a quirk that (a) profile has enabled and (b) applies to this reason code
	var applicableQuirk string
	for _, quirk := range o.quirks {
		if !profile.HasQuirk(quirk.Name) {
			continue
		}
		for _, reason := range quirk.AppliesTo {
			if reason == reasonCode {
				applicableQuirk = quirk.Name
				break
			}
		}
		if applicableQuirk != "" {
			break
		}
	}

	// No applicable quirk - return strict failure
	if applicableQuirk == "" {
		return AttemptResult{
			Success:    false,
			ReasonCode: reasonCode,
			Error:      strictErr,
		}
	}

	// Step 4: Try exactly one quirk attempt
	quirkErr := quirkFn(ctx, applicableQuirk)
	if quirkErr == nil {
		return AttemptResult{
			Success:      true,
			ReasonCode:   reasonCode,
			QuirkApplied: applicableQuirk,
		}
	}

	// Quirk also failed - return quirk failure
	quirkReasonCode := ClassifyError(quirkErr)
	return AttemptResult{
		Success:      false,
		ReasonCode:   quirkReasonCode,
		QuirkApplied: applicableQuirk,
		Error:        quirkErr,
	}
}

// CanApplyQuirk checks if a quirk can be applied for the given peer and reason code.
func (o *Orchestrator) CanApplyQuirk(peerDomain, reasonCode, quirkName string) bool {
	profile := o.profileRegistry.GetProfile(peerDomain)
	if !profile.HasQuirk(quirkName) {
		return false
	}

	for _, quirk := range o.quirks {
		if quirk.Name != quirkName {
			continue
		}
		for _, reason := range quirk.AppliesTo {
			if reason == reasonCode {
				return true
			}
		}
	}
	return false
}
