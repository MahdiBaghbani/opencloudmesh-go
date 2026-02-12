// Wire-format DTOs for POST /ocm/shares.
// See https://github.com/cs3org/OCM-API/blob/615192eeff00bcd479364dfa9c1f91641ac7b505/IETF-RFC.md?plain=1#share-creation-notification
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
	WebApp *WebAppProtocol `json:"webapp,omitempty"`
}

type WebDAVProtocol struct {
	AccessTypes  []string `json:"accessTypes,omitempty"`
	URI          string   `json:"uri"`
	SharedSecret string   `json:"sharedSecret,omitempty"`
	Permissions  []string `json:"permissions"`
	Requirements []string `json:"requirements,omitempty"`
}

const RequirementMustExchangeToken = "must-exchange-token"

func (p *WebDAVProtocol) HasRequirement(req string) bool {
	for _, r := range p.Requirements {
		if r == req {
			return true
		}
	}
	return false
}

type WebAppProtocol struct {
	URI          string `json:"uri"`
	SharedSecret string `json:"sharedSecret,omitempty"`
	ViewMode     string `json:"viewMode,omitempty"`
}

type CreateShareResponse struct {
	RecipientDisplayName string `json:"recipientDisplayName"`
}
