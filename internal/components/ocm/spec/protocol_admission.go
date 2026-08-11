// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package spec

import (
	"encoding/json"
	"errors"
	"slices"
)

// SupportedResourceTypes are the OCM resource types accepted for share creation.
// Only "file" is supported: ocm-go serves a single read-only file via singleFileFS;
// folder shares are not implemented.
// See the OCM-API share-creation contract: https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md?plain=1
var SupportedResourceTypes = []string{"file"}

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
// listed solely to be hard-rejected at admit because MFA enforcement is not
// supported.
var SupportedWebappRequirements = []string{RequirementMustExchangeToken, RequirementMustUseMFA}

// IsSupportedResourceType reports whether resourceType is accepted for share creation.
func IsSupportedResourceType(resourceType string) bool {
	return slices.Contains(SupportedResourceTypes, resourceType)
}

var errUnsupportedProtocolArm = errors.New("UNSUPPORTED")

// ValidateProtocolArms is the protocol-arm admission hook. It admits the
// supported arm keys: name (the protocol shape selector), webdav, and webapp.
// Any other key is rejected as UNSUPPORTED.
func ValidateProtocolArms(raw map[string]json.RawMessage) error {
	for key := range raw {
		if key != "name" && key != ProtocolWebDAV && key != "webapp" {
			return errUnsupportedProtocolArm
		}
	}

	return nil
}

// ValidateProtocolShape checks the minimal current-purpose protocol shape.
// The named "webdav" shape requires a webdav arm. The
// "multi" shape requires at least one supported arm: webdav or webapp. This
// admits a webapp-only arm under "multi" without altering the named "webdav"
// shape behavior.
func ValidateProtocolShape(p Protocol) *ValidationError {
	if p.Name == "" {
		return &ValidationError{Name: "protocol.name", Message: validationRequired}
	}

	if p.Name != "multi" && p.Name != ProtocolWebDAV {
		return &ValidationError{Name: "protocol.name", Message: validationUnsupported}
	}

	if p.Name == ProtocolWebDAV && p.WebDAV == nil {
		return &ValidationError{Name: "protocol.webdav", Message: validationRequired}
	}

	if p.Name == "multi" && p.WebDAV == nil && p.Webapp == nil {
		return &ValidationError{Name: "protocol", Message: validationRequired}
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
		errs = append(errs, ValidationError{Name: "protocol.webdav.uri", Message: validationRequired})
	}

	if p.SharedSecret == "" {
		errs = append(errs, ValidationError{Name: "protocol.webdav.sharedSecret", Message: validationRequired})
	}

	if len(p.Permissions) == 0 {
		errs = append(errs, ValidationError{Name: "protocol.webdav.permissions", Message: validationRequired})
	} else {
		for _, perm := range p.Permissions {
			if !isSupportedWebDAVPermission(perm) {
				errs = append(errs, ValidationError{Name: "protocol.webdav.permissions", Message: validationUnsupported})

				break
			}
		}
	}

	if len(p.AccessTypes) > 0 {
		for _, accessType := range p.AccessTypes {
			if !isSupportedWebDAVAccessType(accessType) {
				errs = append(errs, ValidationError{Name: "protocol.webdav.accessTypes", Message: validationUnsupported})

				break
			}
		}
	}

	for _, req := range p.Requirements {
		if !isSupportedWebDAVRequirement(req) {
			errs = append(errs, ValidationError{Name: "protocol.webdav.requirements", Message: validationUnsupported})

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
		return []ValidationError{{Name: "protocol.webdav.requirements", Message: validationRequired}}
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
	return slices.Contains(SupportedWebDAVRequirements, req)
}

func isSupportedWebDAVAccessType(accessType string) bool {
	return slices.Contains(SupportedWebDAVAccessTypes, accessType)
}

func isSupportedWebDAVPermission(perm string) bool {
	return slices.Contains(SupportedWebDAVPermissions, perm)
}

// ValidateWebappProtocolWire checks webapp wire fields: uri, targets,
// permissions, and sharedSecret are required; permissions must be in
// SupportedWebappPermissions; unknown requirements return UNSUPPORTED;
// must-use-mfa is hard-rejected at admit because MFA enforcement is not
// supported. must-exchange-token remains REQUIRED on the wire; the
// criteria-aware admission seam does not relax that check.
func ValidateWebappProtocolWire(p *WebappProtocol) []ValidationError {
	var errs []ValidationError
	if p == nil {
		return errs
	}

	if p.URI == "" {
		errs = append(errs, ValidationError{Name: "protocol.webapp.uri", Message: validationRequired})
	}

	if len(p.Targets) == 0 {
		errs = append(errs, ValidationError{Name: "protocol.webapp.targets", Message: validationRequired})
	}

	if len(p.Permissions) == 0 {
		errs = append(errs, ValidationError{Name: "protocol.webapp.permissions", Message: validationRequired})
	} else {
		for _, perm := range p.Permissions {
			if !isSupportedWebappPermission(perm) {
				errs = append(errs, ValidationError{Name: "protocol.webapp.permissions", Message: validationUnsupported})

				break
			}
		}
	}

	if len(p.Requirements) == 0 {
		errs = append(errs, ValidationError{Name: fieldProtocolWebappRequirements, Message: validationRequired})
	} else {
		for _, req := range p.Requirements {
			if req == RequirementMustUseMFA {
				errs = append(errs, ValidationError{
					Name:    "protocol.webapp.requirements",
					Message: RequirementMustUseMFA + " rejected at admit; MFA enforcement is not supported",
				})

				continue
			}

			if !isSupportedWebappRequirement(req) {
				errs = append(errs, ValidationError{Name: fieldProtocolWebappRequirements, Message: validationUnsupported})

				break
			}
		}

		if !p.HasRequirement(RequirementMustExchangeToken) {
			errs = append(errs, ValidationError{Name: fieldProtocolWebappRequirements, Message: validationRequired})
		}
	}

	if p.SharedSecret == "" {
		errs = append(errs, ValidationError{Name: "protocol.webapp.sharedSecret", Message: validationRequired})
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
		return []ValidationError{{Name: fieldProtocolWebappRequirements, Message: validationRequired}}
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
	return slices.Contains(SupportedWebappPermissions, perm)
}

func isSupportedWebappRequirement(req string) bool {
	return slices.Contains(SupportedWebappRequirements, req)
}
