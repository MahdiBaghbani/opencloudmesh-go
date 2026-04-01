// Package reason owns the canonical internal peer/federation failure taxonomy
// and explicit translation tables for every outward-facing wire surface.
package reason

import (
	"errors"
	"fmt"
	"net/http"
)

// Canonical internal reason codes for peer and federation failures.
const (
	PeerDiscoveryFailed    = "peer_discovery_failed"
	PeerDiscoveryDisabled  = "peer_discovery_disabled"
	PeerPolicyUnsatisfied  = "peer_policy_unsatisfied"
	PeerCapabilityMismatch = "peer_capability_mismatch"
	PeerUnreachable        = "peer_unreachable"
)

// Peer/federation overlap reason codes migrated from api/errors.go.
// These have peer/federation semantics and are owned by this package.
const (
	DeniedByDenylist   = "denied_by_denylist"
	NotAllowed         = "not_allowed"
	SSRFBlocked        = "ssrf_blocked"
	UntrustedProvider  = "untrusted_provider"
	DiscoveryFailed    = "discovery_failed"
	NetworkError       = "network_error"
)

// Error wraps an error with a canonical reason code for structured error propagation.
type Error struct {
	Reason  string
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Reason, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Reason, e.Message)
}

func (e *Error) Unwrap() error { return e.Cause }

// New creates a reason Error with the given canonical code, message, and cause.
func New(reason, message string, cause error) *Error {
	return &Error{Reason: reason, Message: message, Cause: cause}
}

// Extract returns the canonical reason code from an error, or empty string if not a reason.Error.
func Extract(err error) string {
	var re *Error
	if errors.As(err, &re) {
		return re.Reason
	}
	return ""
}

// OCMStatus returns the HTTP status code for an OCM protocol error response.
func OCMStatus(reason string) int {
	switch reason {
	case PeerDiscoveryFailed:
		return http.StatusServiceUnavailable // 503
	case PeerDiscoveryDisabled:
		return http.StatusServiceUnavailable // 503
	case PeerPolicyUnsatisfied:
		return http.StatusForbidden // 403
	case PeerCapabilityMismatch:
		return http.StatusNotImplemented // 501
	case PeerUnreachable:
		return http.StatusServiceUnavailable // 503
	default:
		return http.StatusInternalServerError
	}
}

// APIStatus returns the HTTP status code for an API envelope error response.
func APIStatus(reason string) int {
	switch reason {
	case PeerDiscoveryFailed:
		return http.StatusBadGateway // 502
	case PeerDiscoveryDisabled:
		return http.StatusNotImplemented // 501
	case PeerPolicyUnsatisfied:
		return http.StatusForbidden // 403
	case PeerCapabilityMismatch:
		return http.StatusBadRequest // 400
	case PeerUnreachable:
		return http.StatusBadGateway // 502
	default:
		return http.StatusInternalServerError
	}
}

// VerifyCode returns the verify-access response reason code string.
func VerifyCode(reason string) string {
	switch reason {
	case PeerDiscoveryFailed:
		return "discovery_failed"
	case PeerDiscoveryDisabled:
		return "discovery_disabled"
	case PeerPolicyUnsatisfied:
		return "policy_denied"
	case PeerCapabilityMismatch:
		return "capability_mismatch"
	case PeerUnreachable:
		return "unreachable"
	default:
		return reason
	}
}

// TranslatePolicyCode maps peertrust.PolicyEngine denial codes to the canonical
// peer taxonomy. Pass-through for codes already in the canonical set.
func TranslatePolicyCode(policyReasonCode string) string {
	switch policyReasonCode {
	case "denied_by_denylist", "not_allowed":
		return PeerPolicyUnsatisfied
	default:
		return policyReasonCode
	}
}
