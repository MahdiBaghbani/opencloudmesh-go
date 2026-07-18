// Minimal protocol admission checks for the current OCM wire contract.
// See https://github.com/cs3org/OCM-API/blob/f9a704f63477134701c0b58b29bb6b98949361dc/IETF-OCM.md?plain=1#share-creation-notification
package spec

import (
	"encoding/json"
	"errors"
)

// SupportedResourceTypes are the OCM resource types accepted for share creation.
var SupportedResourceTypes = []string{"file", "folder"}

// SupportedWebDAVRequirements are the WebDAV protocol requirement values
// this implementation currently recognizes.
var SupportedWebDAVRequirements = []string{RequirementMustExchangeToken}

// IsSupportedResourceType reports whether resourceType is accepted for share creation.
func IsSupportedResourceType(resourceType string) bool {
	for _, supported := range SupportedResourceTypes {
		if resourceType == supported {
			return true
		}
	}
	return false
}

var errUnsupportedProtocolArm = errors.New("UNSUPPORTED")

// ValidateProtocolArms is the protocol-arm admission hook.
func ValidateProtocolArms(raw map[string]json.RawMessage) error {
	for key := range raw {
		if key != "name" && key != "webdav" {
			return errUnsupportedProtocolArm
		}
	}
	return nil
}

// ValidateProtocolShape checks the minimal current-purpose protocol shape: a
// protocol payload must carry a supported name and a webdav arm.
func ValidateProtocolShape(p Protocol) *ValidationError {
	if p.Name == "" {
		return &ValidationError{Name: "protocol.name", Message: "REQUIRED"}
	}
	if p.Name != "multi" && p.Name != "webdav" {
		return &ValidationError{Name: "protocol.name", Message: "UNSUPPORTED"}
	}
	if p.WebDAV == nil {
		return &ValidationError{Name: "protocol.webdav", Message: "REQUIRED"}
	}
	return nil
}

// ValidateWebDAVProtocol checks the WebDAV protocol sub-fields required by
// the OCM wire contract: uri, sharedSecret, and permissions are required,
// and any requirements entry must be one this implementation recognizes.
func ValidateWebDAVProtocol(p *WebDAVProtocol) []ValidationError {
	var errs []ValidationError
	if p == nil {
		return errs
	}
	if p.URI == "" {
		errs = append(errs, ValidationError{Name: "protocol.webdav.uri", Message: "REQUIRED"})
	}
	if p.SharedSecret == "" {
		errs = append(errs, ValidationError{Name: "protocol.webdav.sharedSecret", Message: "REQUIRED"})
	}
	if len(p.Permissions) == 0 {
		errs = append(errs, ValidationError{Name: "protocol.webdav.permissions", Message: "REQUIRED"})
	}
	if len(p.Requirements) == 0 {
		errs = append(errs, ValidationError{Name: "protocol.webdav.requirements", Message: "REQUIRED"})
	} else {
		for _, req := range p.Requirements {
			if !isSupportedWebDAVRequirement(req) {
				errs = append(errs, ValidationError{Name: "protocol.webdav.requirements", Message: "UNSUPPORTED"})
				break
			}
		}
	}
	return errs
}

func isSupportedWebDAVRequirement(req string) bool {
	for _, supported := range SupportedWebDAVRequirements {
		if req == supported {
			return true
		}
	}
	return false
}
