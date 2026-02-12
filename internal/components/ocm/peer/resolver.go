// Package peer provides peer resolvers for OCM signature middleware. Extracts declared peer from request bodies.
package peer

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
)

type Resolver struct{}

func NewResolver() *Resolver {
	return &Resolver{}
}

// ResolveSharesRequest extracts peer from POST /ocm/shares. Prefers sender, falls back to owner; returns provider (last-@).
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

func (p *Resolver) ResolveNotificationsRequest(r *http.Request, body []byte) (string, error) {
	return "", nil
}

func (p *Resolver) ResolveTokenRequest(r *http.Request, body []byte) (string, error) {
	return "", nil
}
