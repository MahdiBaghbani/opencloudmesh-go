package shares

import (
	"fmt"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
)

// ValidationError represents a field-level validation error.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationErrors is a list of validation errors.
type ValidationErrors struct {
	Errors []ValidationError `json:"validationErrors"`
}

func (v *ValidationErrors) Error() string {
	var msgs []string
	for _, e := range v.Errors {
		msgs = append(msgs, fmt.Sprintf("%s: %s", e.Field, e.Message))
	}
	return strings.Join(msgs, "; ")
}

// Add adds a validation error.
func (v *ValidationErrors) Add(field, message string) {
	v.Errors = append(v.Errors, ValidationError{Field: field, Message: message})
}

// HasErrors returns true if there are validation errors.
func (v *ValidationErrors) HasErrors() bool {
	return len(v.Errors) > 0
}

// ValidateNewShareRequest validates an incoming share creation request.
// Returns validation errors if the request is invalid.
// Validation is always strict (sharedSecret is required for WebDAV access).
func ValidateNewShareRequest(req *NewShareRequest) *ValidationErrors {
	errs := &ValidationErrors{}

	// Required fields
	if req.ShareWith == "" {
		errs.Add("shareWith", "required field missing")
	}
	if req.Name == "" {
		errs.Add("name", "required field missing")
	}
	if req.ProviderID == "" {
		errs.Add("providerId", "required field missing")
	}
	if req.Owner == "" {
		errs.Add("owner", "required field missing")
	}
	if req.Sender == "" {
		errs.Add("sender", "required field missing")
	}
	if req.ShareType == "" {
		errs.Add("shareType", "required field missing")
	} else if !isValidShareType(req.ShareType) {
		errs.Add("shareType", "must be one of: user, group, federation")
	}
	if req.ResourceType == "" {
		errs.Add("resourceType", "required field missing")
	}

	// Validate protocol
	if req.Protocol.WebDAV == nil && req.Protocol.WebApp == nil {
		// If name is "multi" or empty, we need at least webdav for file resources
		if req.ResourceType == "file" {
			errs.Add("protocol.webdav", "required for file resources")
		}
	}

	// Validate WebDAV protocol if present
	if req.Protocol.WebDAV != nil {
		validateWebDAVProtocol(req.Protocol.WebDAV, errs)
	}

	return errs
}

// validateWebDAVProtocol validates the WebDAV protocol section.
// Validation is always strict: sharedSecret is required for WebDAV access.
func validateWebDAVProtocol(webdav *WebDAVProtocol, errs *ValidationErrors) {
	// URI is required
	if webdav.URI == "" {
		errs.Add("protocol.webdav.uri", "required field missing")
	}

	// Permissions is required
	if len(webdav.Permissions) == 0 {
		errs.Add("protocol.webdav.permissions", "required field missing")
	} else {
		for _, perm := range webdav.Permissions {
			if !isValidPermission(perm) {
				errs.Add("protocol.webdav.permissions", fmt.Sprintf("invalid permission: %s", perm))
			}
		}
	}

	// sharedSecret is always required for WebDAV access
	if webdav.SharedSecret == "" {
		errs.Add("protocol.webdav.sharedSecret", "required for WebDAV access")
	}

	// Validate requirements
	// Note: must-exchange-token is now accepted and stored for enforcement at access time
	for _, req := range webdav.Requirements {
		switch req {
		case "must-exchange-token":
			// Accepted: stored in share.MustExchangeToken, enforced at WebDAV access
		case "must-use-mfa":
			// Reject by default, could be bypassed in dev mode
			errs.Add("protocol.webdav.requirements", "must-use-mfa not supported")
		default:
			if !isKnownRequirement(req) {
				errs.Add("protocol.webdav.requirements", fmt.Sprintf("unknown requirement: %s", req))
			}
		}
	}
}

func isValidShareType(t string) bool {
	switch t {
	case "user", "group", "federation":
		return true
	}
	return false
}

func isValidPermission(p string) bool {
	switch p {
	case "read", "write", "share":
		return true
	}
	return false
}

func isKnownRequirement(r string) bool {
	switch r {
	case "must-exchange-token", "must-use-mfa", "mfa-enforced":
		return true
	}
	return false
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
