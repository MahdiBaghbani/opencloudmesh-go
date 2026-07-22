// Minimal protocol admission checks for the current OCM wire contract.
// See the OCM-API share-creation contract: https://github.com/cs3org/OCM-API/blob/f9a704f63477134701c0b58b29bb6b98949361dc/IETF-OCM.md?plain=1
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

// SupportedWebDAVAccessTypes are the WebDAV access type values this
// implementation currently recognizes.
var SupportedWebDAVAccessTypes = []string{"remote"}

// SupportedWebDAVPermissions are the WebDAV permission values this
// implementation currently honors.
var SupportedWebDAVPermissions = []string{"read"}

// SupportedWebappPermissions are the webapp protocol permission values this
// implementation honors at admit. They are intentionally distinct from
// SupportedWebDAVPermissions: webapp admits view/read/write/share, while
// WebDAV currently admits only read. Do not merge the two lists.
var SupportedWebappPermissions = []string{"view", "read", "write", "share"}

// SupportedWebappRequirements lists the webapp requirement tokens this
// implementation recognizes. The name is kept for consistency with the other
// Supported* lists, but only must-exchange-token is admitted; must-use-mfa is
// listed solely to be hard-rejected at admit with a GAP note, not because it is
// admitted (enforce-mfa is not implemented yet).
var SupportedWebappRequirements = []string{RequirementMustExchangeToken, RequirementMustUseMFA}

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

// ValidateProtocolArms is the protocol-arm admission hook. It admits the
// supported arm keys: name (the protocol shape selector), webdav, and webapp.
// Any other key is rejected as UNSUPPORTED.
func ValidateProtocolArms(raw map[string]json.RawMessage) error {
	for key := range raw {
		if key != "name" && key != "webdav" && key != "webapp" {
			return errUnsupportedProtocolArm
		}
	}
	return nil
}

// ValidateProtocolShape checks the minimal current-purpose protocol shape.
// The named "webdav" shape requires a webdav arm (legacy behavior). The
// "multi" shape requires at least one supported arm: webdav or webapp. This
// admits a webapp-only arm under "multi" without altering the named "webdav"
// shape behavior.
func ValidateProtocolShape(p Protocol) *ValidationError {
	if p.Name == "" {
		return &ValidationError{Name: "protocol.name", Message: "REQUIRED"}
	}
	if p.Name != "multi" && p.Name != "webdav" {
		return &ValidationError{Name: "protocol.name", Message: "UNSUPPORTED"}
	}
	if p.Name == "webdav" && p.WebDAV == nil {
		return &ValidationError{Name: "protocol.webdav", Message: "REQUIRED"}
	}
	if p.Name == "multi" && p.WebDAV == nil && p.Webapp == nil {
		return &ValidationError{Name: "protocol", Message: "REQUIRED"}
	}
	return nil
}

// ValidateWebDAVProtocol checks the WebDAV protocol sub-fields required by
// the OCM wire contract: uri, sharedSecret, and permissions are required;
// permissions and accessTypes (when present) must be in this
// implementation's supported lists, and any requirements entry must be one
// this implementation recognizes. Missing accessTypes means remote access.
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
	} else {
		for _, perm := range p.Permissions {
			if !isSupportedWebDAVPermission(perm) {
				errs = append(errs, ValidationError{Name: "protocol.webdav.permissions", Message: "UNSUPPORTED"})
				break
			}
		}
	}
	if len(p.AccessTypes) > 0 {
		for _, accessType := range p.AccessTypes {
			if !isSupportedWebDAVAccessType(accessType) {
				errs = append(errs, ValidationError{Name: "protocol.webdav.accessTypes", Message: "UNSUPPORTED"})
				break
			}
		}
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

func isSupportedWebDAVAccessType(accessType string) bool {
	for _, supported := range SupportedWebDAVAccessTypes {
		if accessType == supported {
			return true
		}
	}
	return false
}

func isSupportedWebDAVPermission(perm string) bool {
	for _, supported := range SupportedWebDAVPermissions {
		if perm == supported {
			return true
		}
	}
	return false
}

// ValidateWebappProtocol checks the webapp protocol sub-fields required by the
// OCM wire contract at admit: uri, targets, permissions, requirements, and
// sharedSecret are all required; permissions must be in
// SupportedWebappPermissions (distinct from the WebDAV allow-list);
// requirements must include must-exchange-token and must not contain unknown
// values. must-use-mfa is hard-rejected at admit with an explicit GAP note:
// enforce-mfa is not implemented yet, so this implementation does not claim
// diagram parity for MFA. The GAP rejection is observable here in the returned
// validation errors, not only as a comment.
func ValidateWebappProtocol(p *WebappProtocol) []ValidationError {
	var errs []ValidationError
	if p == nil {
		return errs
	}
	if p.URI == "" {
		errs = append(errs, ValidationError{Name: "protocol.webapp.uri", Message: "REQUIRED"})
	}
	if len(p.Targets) == 0 {
		errs = append(errs, ValidationError{Name: "protocol.webapp.targets", Message: "REQUIRED"})
	}
	if len(p.Permissions) == 0 {
		errs = append(errs, ValidationError{Name: "protocol.webapp.permissions", Message: "REQUIRED"})
	} else {
		for _, perm := range p.Permissions {
			if !isSupportedWebappPermission(perm) {
				errs = append(errs, ValidationError{Name: "protocol.webapp.permissions", Message: "UNSUPPORTED"})
				break
			}
		}
	}
	if len(p.Requirements) == 0 {
		errs = append(errs, ValidationError{Name: "protocol.webapp.requirements", Message: "REQUIRED"})
	} else {
		for _, req := range p.Requirements {
			if req == RequirementMustUseMFA {
				errs = append(errs, ValidationError{
					Name:    "protocol.webapp.requirements",
					Message: "GAP: must-use-mfa rejected at admit; enforce-mfa is not implemented yet",
				})
				continue
			}
			if !isSupportedWebappRequirement(req) {
				errs = append(errs, ValidationError{Name: "protocol.webapp.requirements", Message: "UNSUPPORTED"})
				break
			}
		}
		if !p.HasRequirement(RequirementMustExchangeToken) {
			errs = append(errs, ValidationError{Name: "protocol.webapp.requirements", Message: "REQUIRED"})
		}
	}
	if p.SharedSecret == "" {
		errs = append(errs, ValidationError{Name: "protocol.webapp.sharedSecret", Message: "REQUIRED"})
	}
	return errs
}

func isSupportedWebappPermission(perm string) bool {
	for _, supported := range SupportedWebappPermissions {
		if perm == supported {
			return true
		}
	}
	return false
}

func isSupportedWebappRequirement(req string) bool {
	for _, supported := range SupportedWebappRequirements {
		if req == supported {
			return true
		}
	}
	return false
}
