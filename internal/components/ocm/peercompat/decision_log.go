// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package peercompat

// CompatibilityDecisionLog freezes compatibility decision log fields.
type CompatibilityDecisionLog struct {
	RequestID          string
	PeerDomain         string
	Profile            string
	Operation          string
	Decision           string
	ReasonCode         string
	CompatibilityScope string
	Quirk              string
}

// SlogAttrs returns stable key/value pairs for compatibility decision logs.
func (entry CompatibilityDecisionLog) SlogAttrs() []any {
	attrs := make([]any, 0, 16)
	if entry.RequestID != "" {
		attrs = append(attrs, "request_id", entry.RequestID)
	}
	attrs = append(attrs,
		"peer_domain", entry.PeerDomain,
		"profile", entry.Profile,
		"operation", entry.Operation,
		"decision", entry.Decision,
		"reason_code", entry.ReasonCode,
		"compatibility_scope", entry.CompatibilityScope,
	)
	if entry.Quirk != "" {
		attrs = append(attrs, "quirk", entry.Quirk)
	}
	return attrs
}
