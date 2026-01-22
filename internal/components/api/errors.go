// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

// Package api provides common HTTP API utilities including error handling.
package api

import (
	"encoding/json"
	"net/http"
)

// Deterministic reason codes for stable error classification.
// These codes should remain stable across versions for client compatibility.
const (
	// Authentication and authorization
	ReasonUnauthenticated     = "unauthenticated"
	ReasonUnauthorized        = "unauthorized"
	ReasonSessionExpired      = "session_expired"
	ReasonInvalidCredentials  = "invalid_credentials"

	// Signature verification
	ReasonSignatureRequired   = "signature_required"
	ReasonSignatureInvalid    = "signature_invalid"
	ReasonSignatureMismatch   = "signature_mismatch"
	ReasonDigestMismatch      = "digest_mismatch"

	// Rate limiting
	ReasonRateLimited         = "rate_limited"

	// Request validation
	ReasonBadRequest          = "bad_request"
	ReasonMissingField        = "missing_field"
	ReasonInvalidField        = "invalid_field"
	ReasonNotFound            = "not_found"
	ReasonConflict            = "conflict"

	// SSRF and network
	ReasonSSRFBlocked         = "ssrf_blocked"
	ReasonNetworkError        = "network_error"
	ReasonPeerUnreachable     = "peer_unreachable"

	// Federation policy
	ReasonDeniedByDenylist    = "denied_by_denylist"
	ReasonNotAllowed          = "not_allowed"

	// Server errors
	ReasonInternalError       = "internal_error"
	ReasonNotImplemented      = "not_implemented"
)

// ErrorEnvelope is the standard error response format.
// All error responses should use this structure for consistency.
type ErrorEnvelope struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail contains the error information.
type ErrorDetail struct {
	Code       string `json:"code"`       // HTTP status text (e.g., "forbidden")
	ReasonCode string `json:"reason_code"` // Deterministic reason code
	Message    string `json:"message"`     // Human-readable message
}

// WriteError writes a standardized JSON error response.
func WriteError(w http.ResponseWriter, statusCode int, reasonCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	envelope := ErrorEnvelope{
		Error: ErrorDetail{
			Code:       http.StatusText(statusCode),
			ReasonCode: reasonCode,
			Message:    message,
		},
	}

	json.NewEncoder(w).Encode(envelope)
}

// Common error helpers for frequently used patterns

// WriteUnauthorized writes a 401 Unauthorized error.
func WriteUnauthorized(w http.ResponseWriter, reasonCode, message string) {
	WriteError(w, http.StatusUnauthorized, reasonCode, message)
}

// WriteForbidden writes a 403 Forbidden error.
func WriteForbidden(w http.ResponseWriter, reasonCode, message string) {
	WriteError(w, http.StatusForbidden, reasonCode, message)
}

// WriteNotFound writes a 404 Not Found error.
func WriteNotFound(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusNotFound, ReasonNotFound, message)
}

// WriteBadRequest writes a 400 Bad Request error.
func WriteBadRequest(w http.ResponseWriter, reasonCode, message string) {
	WriteError(w, http.StatusBadRequest, reasonCode, message)
}

// WriteConflict writes a 409 Conflict error.
func WriteConflict(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusConflict, ReasonConflict, message)
}

// WriteTooManyRequests writes a 429 Too Many Requests error.
func WriteTooManyRequests(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusTooManyRequests, ReasonRateLimited, message)
}

// WriteInternalError writes a 500 Internal Server Error.
// Be careful not to leak sensitive information in the message.
func WriteInternalError(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusInternalServerError, ReasonInternalError, message)
}

// WriteNotImplemented writes a 501 Not Implemented error.
func WriteNotImplemented(w http.ResponseWriter, feature string) {
	WriteError(w, http.StatusNotImplemented, ReasonNotImplemented, feature+" not implemented yet")
}
