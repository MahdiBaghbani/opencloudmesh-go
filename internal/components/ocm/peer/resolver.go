// Package peer provides declared-peer resolvers for OCM signature middleware.
// Each resolver extracts the declared peer identity from a specific OCM protocol
// request body so the signature middleware can verify the request against that peer.
package peer

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
)

// Resolver extracts declared peer identity from OCM protocol request bodies.
type Resolver struct{}

// NewResolver creates a new peer resolver.
func NewResolver() *Resolver {
	return &Resolver{}
}

// ResolveSharesRequest extracts the peer from POST /ocm/shares.
// Prefers sender, falls back to owner. Parses as OCM address using last-@
// and returns the provider part only.
func (p *Resolver) ResolveSharesRequest(r *http.Request, body []byte) (string, error) {
	var req struct {
		Sender string `json:"sender"`
		Owner  string `json:"owner"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		return "", fmt.Errorf("failed to parse shares request: %w", err)
	}

	addr := req.Sender
	if addr == "" {
		addr = req.Owner
	}

	if addr == "" {
		return "", fmt.Errorf("no sender or owner in shares request")
	}

	_, provider, err := address.Parse(addr)
	if err != nil {
		return "", err
	}

	return provider, nil
}

// ResolveInviteAcceptedRequest extracts the peer from POST /ocm/invite-accepted.
// Returns recipientProvider as-is (must be a schemeless authority).
func (p *Resolver) ResolveInviteAcceptedRequest(r *http.Request, body []byte) (string, error) {
	var req struct {
		RecipientProvider string `json:"recipientProvider"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		return "", fmt.Errorf("failed to parse invite-accepted request: %w", err)
	}

	if req.RecipientProvider == "" {
		return "", fmt.Errorf("no recipientProvider in invite-accepted request")
	}

	return req.RecipientProvider, nil
}

// ResolveNotificationsRequest extracts the peer from POST /ocm/notifications.
// Notifications have no sender field; peer identity comes from the signature keyId.
func (p *Resolver) ResolveNotificationsRequest(r *http.Request, body []byte) (string, error) {
	return "", nil
}

// ResolveTokenRequest extracts the peer from POST /ocm/token.
// Token exchange relies on signature-based authentication; no body-level peer.
func (p *Resolver) ResolveTokenRequest(r *http.Request, body []byte) (string, error) {
	return "", nil
}
