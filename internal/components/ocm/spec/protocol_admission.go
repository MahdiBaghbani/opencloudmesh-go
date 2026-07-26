// Minimal protocol admission checks for the current OCM wire contract.
// See the OCM-API share-creation contract: https://github.com/cs3org/OCM-API/blob/a5b5da6e17a598266b09a0445db8ac53b29daefc/IETF-OCM.md?plain=1
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

// ValidateWebDAVProtocolWire checks WebDAV wire fields only: uri, sharedSecret,
// and permissions are required; permissions and accessTypes (when present) must
// be in this implementation's supported lists; unknown requirements return
// UNSUPPORTED. Empty requirements are valid on the wire.
func ValidateWebDAVProtocolWire(p *WebDAVProtocol) []ValidationError {
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
	for _, req := range p.Requirements {
		if !isSupportedWebDAVRequirement(req) {
			errs = append(errs, ValidationError{Name: "protocol.webdav.requirements", Message: "UNSUPPORTED"})
			break
		}
	}
	return errs
}

// ValidateWebDAVRequirementsAdmission applies the criteria-aware requirements
// seam. When localRequires is true, empty requirements are REQUIRED; when
// false, empty requirements produce no admission error. Non-empty requirements
// produce no admission error either way (wire validation covers unknown values).
func ValidateWebDAVRequirementsAdmission(localRequires bool, reqs []string) []ValidationError {
	if localRequires && len(reqs) == 0 {
		return []ValidationError{{Name: "protocol.webdav.requirements", Message: "REQUIRED"}}
	}
	return nil
}

// ValidateWebDAVProtocol is the strict wrapper: wire validation plus
// requirements admission with localRequires=true.
func ValidateWebDAVProtocol(p *WebDAVProtocol) []ValidationError {
	if p == nil {
		return nil
	}
	errs := ValidateWebDAVProtocolWire(p)
	errs = append(errs, ValidateWebDAVRequirementsAdmission(true, p.Requirements)...)
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

// ValidateWebappProtocolWire checks webapp wire fields: uri, targets,
// permissions, and sharedSecret are required; permissions must be in
// SupportedWebappPermissions; unknown requirements return UNSUPPORTED;
// must-use-mfa is hard-rejected with a GAP note because MFA is not
// implemented. must-exchange-token remains REQUIRED on the wire; the
// criteria-aware admission seam does not relax that check.
func ValidateWebappProtocolWire(p *WebappProtocol) []ValidationError {
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
					Message: "GAP: " + RequirementMustUseMFA + " rejected at admit; enforce-mfa is not implemented yet",
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

// ValidateWebappRequirementsAdmission applies the criteria-aware requirements
// seam. When localRequires is true, empty requirements are REQUIRED; when
// false, empty requirements produce no admission error. Non-empty requirements
// produce no admission error either way. This does not replace wire checks for
// must-exchange-token.
func ValidateWebappRequirementsAdmission(localRequires bool, reqs []string) []ValidationError {
	if localRequires && len(reqs) == 0 {
		return []ValidationError{{Name: "protocol.webapp.requirements", Message: "REQUIRED"}}
	}
	return nil
}

// ValidateWebappProtocol is the strict wrapper: wire validation plus
// requirements admission with localRequires=true. Admission errors that
// already appear identically from wire are skipped so empty requirements
// still yield a single REQUIRED error.
func ValidateWebappProtocol(p *WebappProtocol) []ValidationError {
	if p == nil {
		return nil
	}
	errs := ValidateWebappProtocolWire(p)
	for _, adm := range ValidateWebappRequirementsAdmission(true, p.Requirements) {
		if hasExactValidationError(errs, adm) {
			continue
		}
		errs = append(errs, adm)
	}
	return errs
}

func hasExactValidationError(errs []ValidationError, want ValidationError) bool {
	for _, e := range errs {
		if e.Name == want.Name && e.Message == want.Message {
			return true
		}
	}
	return false
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
