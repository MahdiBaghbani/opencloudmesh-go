// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

import (
	"context"
)

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
