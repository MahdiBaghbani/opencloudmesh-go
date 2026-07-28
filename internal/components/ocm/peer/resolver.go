// Package peer provides peer resolvers for OCM signature middleware. Extracts declared peer from request bodies.
package peer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
)

// Resolver extracts the declared peer host from OCM request bodies.
type Resolver struct{}

func NewResolver() *Resolver { //nolint:revive // exported: trivial constructor for stateless Resolver
	return &Resolver{}
}

// ResolveSharesRequest extracts peer from POST /ocm/shares. Prefers sender, falls back to owner; returns provider (last-@).
func (p *Resolver) ResolveSharesRequest(_ *http.Request, body []byte) (string, error) {
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

// ResolveInviteAcceptedRequest extracts the recipient provider from POST /ocm/invite-accepted.
func (p *Resolver) ResolveInviteAcceptedRequest(_ *http.Request, body []byte) (string, error) {
	var req struct {
		RecipientProvider string `json:"recipientProvider"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		return "", fmt.Errorf("failed to parse invite-accepted request: %w", err)
	}

	if req.RecipientProvider == "" {
		return "", fmt.Errorf("no recipientProvider in invite-accepted request")
	}

	if strings.Contains(req.RecipientProvider, "://") {
		return "", fmt.Errorf("invalid recipientProvider in invite-accepted request")
	}

	return req.RecipientProvider, nil
}

// ResolveTokenRequest extracts the client_id from a token request body.
func (p *Resolver) ResolveTokenRequest(_ *http.Request, body []byte) (string, error) {
	clientID, err := parseTokenClientID(body)
	if err != nil {
		return "", err
	}

	if strings.Contains(clientID, "://") {
		return "", fmt.Errorf("invalid client_id in token request")
	}

	return clientID, nil
}

func parseTokenClientID(body []byte) (string, error) {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", fmt.Errorf("failed to parse token request: %w", err)
	}

	clientID := strings.TrimSpace(values.Get("client_id"))
	if clientID == "" {
		return "", fmt.Errorf("no client_id in token request")
	}

	return clientID, nil
}
