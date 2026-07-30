// Package incoming provides incoming share models, repository, and the
// POST /ocm/shares handler.
package incoming

import (
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
)

// IncomingShare holds a received share scoped to a local recipient user.
type IncomingShare struct {
	ShareID    string `json:"shareId"` // local UUIDv7
	ProviderID string `json:"providerId"`
	SenderHost string `json:"senderHost"`

	WebDAVID     string `json:"webdavId,omitempty"`
	SharedSecret string `json:"-"`

	Permissions []string `json:"permissions"`

	Owner             string `json:"owner"`
	Sender            string `json:"sender"`
	ShareWith         string `json:"shareWith"`
	Name              string `json:"name"`
	Description       string `json:"description,omitempty"`
	ResourceType      string `json:"resourceType"`
	ShareType         string `json:"shareType"`
	OwnerDisplayName  string `json:"ownerDisplayName,omitempty"`
	SenderDisplayName string `json:"senderDisplayName,omitempty"`
	Expiration        *int64 `json:"expiration,omitempty"`

	// Webapp arm fields. Stored alongside the WebDAV Permissions field; the
	// two permission lists are distinct and must not be merged.
	WebappPermissions []string `json:"webappPermissions,omitempty"`
	WebappURI         string   `json:"webappUri,omitempty"`
	WebappTargets     []string `json:"webappTargets,omitempty"`

	// ProtocolName is the stored protocol.name from the wire payload. Legacy
	// rows have an empty value; never synthesize "multi" for them.
	ProtocolName string `json:"protocolName,omitempty"`

	RecipientUserID      string `json:"-"`
	RecipientDisplayName string `json:"-"`

	Requirements []string `json:"requirements,omitempty"`

	Status    shares.ShareStatus `json:"status"`
	CreatedAt time.Time          `json:"createdAt"`
	UpdatedAt time.Time          `json:"updatedAt"`
	OwnerHost string             `json:"ownerHost,omitempty"`
}
