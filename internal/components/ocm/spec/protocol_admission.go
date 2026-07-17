// Minimal protocol admission checks for the current OCM wire contract.
// See https://github.com/cs3org/OCM-API/blob/f9a704f63477134701c0b58b29bb6b98949361dc/IETF-OCM.md?plain=1#share-creation-notification
package spec

import "encoding/json"

// SupportedWebDAVRequirements are the WebDAV protocol requirement values
// this implementation currently recognizes.
var SupportedWebDAVRequirements = []string{RequirementMustExchangeToken}

// ValidateProtocolArms is the protocol-arm admission hook.
func ValidateProtocolArms(raw map[string]json.RawMessage) error {
	_ = raw
	return nil
}

// ValidateProtocolShape checks the minimal current-purpose protocol shape: a
// protocol payload must carry a name. Rejecting more than one populated
// protocol arm is not implemented yet.
func ValidateProtocolShape(p Protocol) *ValidationError {
	if p.Name == "" {
		return &ValidationError{Name: "protocol.name", Message: "REQUIRED"}
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
	for _, req := range p.Requirements {
		if !isSupportedWebDAVRequirement(req) {
			errs = append(errs, ValidationError{Name: "protocol.webdav.requirements", Message: "UNSUPPORTED"})
			break
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
