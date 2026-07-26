package spec

// Canonical OCM protocol requirement wire values (IETF-RFC / OpenAPI).
// Used on share WebDAV/webapp arms and by access/admission call sites.
const (
	RequirementMustExchangeToken = "must-exchange-token"

	// RequirementMustUseMFA is recognized only to be hard-rejected at admit;
	// MFA enforcement is not supported.
	RequirementMustUseMFA = "must-use-mfa"
)
