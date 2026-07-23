// Wire-format DTOs for POST /ocm/shares.
// See the OCM-API share-creation contract: https://github.com/cs3org/OCM-API/blob/f9a704f63477134701c0b58b29bb6b98949361dc/IETF-OCM.md?plain=1
package spec

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

type Protocol struct {
	Name   string          `json:"name,omitempty"`
	WebDAV *WebDAVProtocol `json:"webdav,omitempty"`
	Webapp *WebappProtocol `json:"webapp,omitempty"`
}

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
// exception belongs to the P4 wire/admission split and is out of scope.
type WebappProtocol struct {
	URI          string   `json:"uri"`
	Targets      []string `json:"targets"`
	Permissions  []string `json:"permissions"`
	Requirements []string `json:"requirements"`
	SharedSecret string   `json:"sharedSecret"`
}

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

type CreateShareResponse struct {
	RecipientDisplayName string `json:"recipientDisplayName"`
}
