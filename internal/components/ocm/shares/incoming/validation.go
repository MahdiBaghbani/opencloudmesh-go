package incoming

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
)

// ValidationError is a spec-aligned field-level validation error.
type ValidationError struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

// OCMErrorResponse is the spec base Error schema (used for 400/403/501).
type OCMErrorResponse struct {
	Message          string            `json:"message"`
	ValidationErrors []ValidationError `json:"validationErrors,omitempty"`
}

// ValidateRequiredFields checks that all spec-required NewShare fields are present.
// Returns a non-nil slice of ValidationError for each missing field.
// Does NOT check protocol.name (that is handled by the share handler after
// computing strictPayloadValidation).
func ValidateRequiredFields(req *shares.NewShareRequest) []ValidationError {
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

	// Protocol is required: must have at least one of Name, WebDAV, or WebApp.
	if req.Protocol.Name == "" && req.Protocol.WebDAV == nil && req.Protocol.WebApp == nil {
		errs = append(errs, ValidationError{Name: "protocol", Message: "REQUIRED"})
	}

	return errs
}

// WriteValidationError writes a 400 response with the spec's validationErrors format.
// Used only by POST /ocm/shares. Local API endpoints use api.WriteBadRequest instead.
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
	writeOCMError(w, http.StatusNotImplemented, "SHARE_TYPE_NOT_SUPPORTED")
}

// WriteProtocolNotSupported writes a 501 response for unsupported protocols.
func WriteProtocolNotSupported(w http.ResponseWriter) {
	writeOCMError(w, http.StatusNotImplemented, "PROTOCOL_NOT_SUPPORTED")
}

// writeOCMError writes a base Error schema response (no validationErrors).
func writeOCMError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(OCMErrorResponse{Message: message})
}

// ExtractSenderHost extracts the host (provider) from an OCM address using last-@ semantics.
// The identifier part may contain '@' (e.g. email addresses).
func ExtractSenderHost(sender string) string {
	_, provider, err := address.Parse(sender)
	if err != nil {
		return ""
	}
	return strings.ToLower(provider)
}

// IsAbsoluteURI checks if a URI is absolute (contains ://).
func IsAbsoluteURI(uri string) bool {
	return strings.Contains(uri, "://")
}
