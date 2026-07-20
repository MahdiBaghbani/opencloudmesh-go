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
	if strings.Contains(req.RecipientProvider, "://") {
		return "", fmt.Errorf("invalid recipientProvider in invite-accepted request")
	}

	return req.RecipientProvider, nil
}

func (p *Resolver) ResolveTokenRequest(r *http.Request, body []byte) (string, error) {
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
