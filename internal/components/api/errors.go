// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

// Package api provides shared HTTP API handlers (auth, health) and standardized error responses.
package api

import (
	"encoding/json"
	"net/http"
)

// Deterministic reason codes for error classification; keep stable for client compatibility.
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
type ErrorEnvelope struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail holds code, reason_code, and message for API errors.
type ErrorDetail struct {
	Code       string `json:"code"`       // HTTP status text (e.g., "forbidden")
	ReasonCode string `json:"reason_code"` // Deterministic reason code
	Message    string `json:"message"`     // Human-readable message
}

// WriteError sends a standardized JSON error envelope.
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

// WriteUnauthorized sends 401 with the given reason code and message.
func WriteUnauthorized(w http.ResponseWriter, reasonCode, message string) {
	WriteError(w, http.StatusUnauthorized, reasonCode, message)
}

// WriteForbidden sends 403 with the given reason code and message.
func WriteForbidden(w http.ResponseWriter, reasonCode, message string) {
	WriteError(w, http.StatusForbidden, reasonCode, message)
}

// WriteNotFound sends 404 with reason not_found.
func WriteNotFound(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusNotFound, ReasonNotFound, message)
}

// WriteBadRequest sends 400 with the given reason code and message.
func WriteBadRequest(w http.ResponseWriter, reasonCode, message string) {
	WriteError(w, http.StatusBadRequest, reasonCode, message)
}

// WriteConflict sends 409 with reason conflict.
func WriteConflict(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusConflict, ReasonConflict, message)
}

// WriteTooManyRequests sends 429 with reason rate_limited.
func WriteTooManyRequests(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusTooManyRequests, ReasonRateLimited, message)
}

// WriteInternalError sends 500. Avoid leaking sensitive data in the message.
func WriteInternalError(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusInternalServerError, ReasonInternalError, message)
}

// WriteNotImplemented sends 501 with a feature name.
func WriteNotImplemented(w http.ResponseWriter, feature string) {
	WriteError(w, http.StatusNotImplemented, ReasonNotImplemented, feature+" not implemented yet")
}
