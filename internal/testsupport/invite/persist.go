package invite

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
)

// persistedOutgoingInvite mirrors store.OutgoingInvite JSON on disk.
type persistedOutgoingInvite struct {
	Token                string `json:"token"`
	Status               string `json:"status"`
	AcceptedProviderFQDN string `json:"acceptedProviderFqdn,omitempty"`
}

// OutgoingStatus reads json persistence at dataDir/data/outgoing_invites.json and
// returns the status for the invite matching token.
func OutgoingStatus(dataDir, token string) (invites.InviteStatus, string, error) {
	path := filepath.Join(dataDir, "data", "outgoing_invites.json")

	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read outgoing invites: %w", err)
	}

	var invitesByID map[string]persistedOutgoingInvite
	if err := json.Unmarshal(raw, &invitesByID); err != nil {
		return "", "", fmt.Errorf("decode outgoing invites: %w", err)
	}

	for _, inv := range invitesByID {
		if inv.Token == token {
			return invites.InviteStatus(inv.Status), inv.AcceptedProviderFQDN, nil
		}
	}

	return "", "", fmt.Errorf("outgoing invite token %q not found in %s", token, path)
}
