// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// OCM spec error and validation types.
// See the OCM-API share-creation contract: https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md?plain=1
package spec

import (
	"encoding/json"
	"net/http"
)

// ValidationError carries one field-level validation error in an OCM error response.
type ValidationError struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

// OCMErrorResponse carries the message and optional validation errors written for failed OCM requests.
type OCMErrorResponse struct {
	Message          string            `json:"message"`
	ValidationErrors []ValidationError `json:"validationErrors,omitempty"`
}

// ValidateRequiredFields returns ValidationError for each missing spec-required NewShare field. protocol.name handled by handler.
func ValidateRequiredFields(req *NewShareRequest) []ValidationError {
	var errs []ValidationError

	if req.ShareWith == "" {
		errs = append(errs, ValidationError{Name: "shareWith", Message: "REQUIRED"})
	}

	if req.Name == "" {
		errs = append(errs, ValidationError{Name: "name", Message: "REQUIRED"})
	}

	if req.ProviderID == "" {
		errs = append(errs, ValidationError{Name: "providerId", Message: "REQUIRED"})
	}

	if req.Owner == "" {
		errs = append(errs, ValidationError{Name: "owner", Message: "REQUIRED"})
	}

	if req.Sender == "" {
		errs = append(errs, ValidationError{Name: "sender", Message: "REQUIRED"})
	}

	if req.ShareType == "" {
		errs = append(errs, ValidationError{Name: "shareType", Message: "REQUIRED"})
	}

	if req.ResourceType == "" {
		errs = append(errs, ValidationError{Name: "resourceType", Message: "REQUIRED"})
	}

	if req.Protocol.Name == "" && req.Protocol.WebDAV == nil {
		errs = append(errs, ValidationError{Name: "protocol", Message: "REQUIRED"})
	}

	return errs
}

// WriteValidationError writes a 400 OCM error response with the given message and validation errors.
func WriteValidationError(w http.ResponseWriter, message string, errors []ValidationError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	//nolint:errcheck,errchkjson // response already committed after WriteHeader; write error cannot be recovered or meaningfully handled; payload encodes to fixed JSON, so encode error is always nil
	json.NewEncoder(w).Encode(OCMErrorResponse{
		Message:          message,
		ValidationErrors: errors,
	})
}

// WriteShareTypeNotSupported writes a 501 response for unsupported share types.
func WriteShareTypeNotSupported(w http.ResponseWriter) {
	WriteOCMError(w, http.StatusNotImplemented, "SHARE_TYPE_NOT_SUPPORTED")
}

// WriteResourceTypeNotSupported writes a 501 response for unsupported resource types.
func WriteResourceTypeNotSupported(w http.ResponseWriter) {
	WriteOCMError(w, http.StatusNotImplemented, "RESOURCE_TYPE_NOT_SUPPORTED")
}

// WriteProtocolNotSupported writes a 501 response for unsupported protocols.
func WriteProtocolNotSupported(w http.ResponseWriter) {
	WriteOCMError(w, http.StatusNotImplemented, "PROTOCOL_NOT_SUPPORTED")
}

// WriteOCMError writes a base Error schema response (no validationErrors).
func WriteOCMError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	//nolint:errcheck,errchkjson // response already committed after WriteHeader; write error cannot be recovered or meaningfully handled; payload encodes to fixed JSON, so encode error is always nil
	json.NewEncoder(w).Encode(OCMErrorResponse{Message: message})
}
