// OCM spec error and validation types.
// See https://github.com/cs3org/OCM-API/blob/615192eeff00bcd479364dfa9c1f91641ac7b505/IETF-RFC.md?plain=1#share-creation-notification
package spec

import (
	"encoding/json"
	"net/http"
)

type ValidationError struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

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
	if req.Protocol.Name == "" && req.Protocol.WebDAV == nil && req.Protocol.WebApp == nil {
		errs = append(errs, ValidationError{Name: "protocol", Message: "REQUIRED"})
	}

	return errs
}

func WriteValidationError(w http.ResponseWriter, message string, errors []ValidationError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(OCMErrorResponse{
		Message:          message,
		ValidationErrors: errors,
	})
}

// WriteShareTypeNotSupported writes a 501 response for unsupported share types.
func WriteShareTypeNotSupported(w http.ResponseWriter) {
	WriteOCMError(w, http.StatusNotImplemented, "SHARE_TYPE_NOT_SUPPORTED")
}

// WriteProtocolNotSupported writes a 501 response for unsupported protocols.
func WriteProtocolNotSupported(w http.ResponseWriter) {
	WriteOCMError(w, http.StatusNotImplemented, "PROTOCOL_NOT_SUPPORTED")
}

// WriteOCMError writes a base Error schema response (no validationErrors).
func WriteOCMError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(OCMErrorResponse{Message: message})
}
