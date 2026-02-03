// Wire-format DTOs for POST /ocm/shares.
// See OCM-API spec v1.2.2 NewShare and related schemas.
package spec

// NewShareRequest represents an incoming POST /ocm/shares request body.
type NewShareRequest struct {
	ShareWith         string   `json:"shareWith"`
	Name              string   `json:"name"`
	Description       string   `json:"description,omitempty"`
	ProviderID        string   `json:"providerId"`
	Owner             string   `json:"owner"`
	Sender            string   `json:"sender"`
	OwnerDisplayName  string   `json:"ownerDisplayName,omitempty"`
	SenderDisplayName string   `json:"senderDisplayName,omitempty"`
	ShareType         string   `json:"shareType"`
	ResourceType      string   `json:"resourceType"`
	Expiration        *int64   `json:"expiration,omitempty"`
	Protocol          Protocol `json:"protocol"`
}

// Protocol contains protocol-specific options.
type Protocol struct {
	Name   string          `json:"name,omitempty"`
	WebDAV *WebDAVProtocol `json:"webdav,omitempty"`
	WebApp *WebAppProtocol `json:"webapp,omitempty"`
}

// WebDAVProtocol contains WebDAV access options.
type WebDAVProtocol struct {
	AccessTypes  []string `json:"accessTypes,omitempty"`
	URI          string   `json:"uri"`
	SharedSecret string   `json:"sharedSecret,omitempty"`
	Permissions  []string `json:"permissions"`
	Requirements []string `json:"requirements,omitempty"`
}

// RequirementMustExchangeToken is the requirement indicating token exchange is required.
const RequirementMustExchangeToken = "must-exchange-token"

// HasRequirement checks if the protocol has a specific requirement.
func (p *WebDAVProtocol) HasRequirement(req string) bool {
	for _, r := range p.Requirements {
		if r == req {
			return true
		}
	}
	return false
}

// WebAppProtocol contains webapp access options.
type WebAppProtocol struct {
	URI          string `json:"uri"`
	SharedSecret string `json:"sharedSecret,omitempty"`
	ViewMode     string `json:"viewMode,omitempty"`
}

// CreateShareResponse is the spec-aligned 201/200 response for POST /ocm/shares.
// Only includes spec-required fields; do not serialize the full IncomingShare.
type CreateShareResponse struct {
	RecipientDisplayName string `json:"recipientDisplayName"`
}
