// Wire-format DTOs for POST /ocm/shares.
// See the OCM-API share-creation contract: https://github.com/cs3org/OCM-API/blob/a5b5da6e17a598266b09a0445db8ac53b29daefc/IETF-OCM.md?plain=1
package spec

// NewShareRequest carries the wire body for POST /ocm/shares.
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

// Protocol carries the named protocol arm of a share request (webdav or webapp).
type Protocol struct {
	Name   string          `json:"name,omitempty"`
	WebDAV *WebDAVProtocol `json:"webdav,omitempty"`
	Webapp *WebappProtocol `json:"webapp,omitempty"`
}

// WebDAVProtocol carries the WebDAV protocol fields of a share request.
type WebDAVProtocol struct {
	AccessTypes  []string `json:"accessTypes,omitempty"`
	URI          string   `json:"uri"`
	SharedSecret string   `json:"sharedSecret,omitempty"`
	Permissions  []string `json:"permissions"`
	Requirements []string `json:"requirements,omitempty"`
}

// WebappProtocol is the webapp protocol arm. Its permissions are distinct
// from WebDAV permissions (see SupportedWebappPermissions) and must not be
// merged into a shared permissions list. sharedSecret is IETF REQUIRED at
// admit time, so it has no omitempty here; the redacted outbound-view
// exception is handled at the outbound redaction layer and is out of scope here.
type WebappProtocol struct {
	URI          string   `json:"uri"`
	Targets      []string `json:"targets"`
	Permissions  []string `json:"permissions"`
	Requirements []string `json:"requirements"`
	SharedSecret string   `json:"sharedSecret"`
}

// HasRequirement reports whether the WebDAV arm advertises req.
func (p *WebDAVProtocol) HasRequirement(req string) bool {
	for _, r := range p.Requirements {
		if r == req {
			return true
		}
	}

	return false
}

// HasRequirement reports whether the webapp arm advertises req.
func (p *WebappProtocol) HasRequirement(req string) bool {
	if p == nil {
		return false
	}

	for _, r := range p.Requirements {
		if r == req {
			return true
		}
	}

	return false
}

// CreateShareResponse carries the wire body returned after creating a share.
type CreateShareResponse struct {
	RecipientDisplayName string `json:"recipientDisplayName"`
}
